import datetime
import hashlib
import hmac
import json
import uuid
from collections import defaultdict
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.core import signing
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import Device, Event, LedgerHead, Order

REQUIRED = {
    "RESTOCK": {"depot", "item", "qty"},
    "DELIVERY": {"order_id", "depot", "item", "qty", "amount_due"},
    "PAYMENT": {"order_id", "amount"},
    "SENSOR": {"tank_id", "level_pct"},
    "FAILED_ATTEMPT": {"order_id", "reason"},
}
NUMERIC = {"qty", "amount_due", "amount", "level_pct"}
QR_SALT = "order-qr"
OTP_ITER = 10000        # PBKDF2 rounds for the offline OTP check on the phone


def _sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _int(x):
    try:
        return max(0, int(x))
    except (TypeError, ValueError):
        return 0


# ---------- QR ----------
def issue_qr(order_id):
    return signing.dumps({"o": order_id}, salt=QR_SALT)


def verify_qr(token, order_id):
    try:
        data = signing.loads(token, salt=QR_SALT, max_age=getattr(settings, "QR_MAX_AGE", 7 * 86400))
    except signing.BadSignature:
        return False
    return data.get("o") == order_id


# ---------- delivery OTP: derived from the order id + a nonce, so nothing is stored ----------
def otp_for(order_id, nonce=0):
    d = hmac.new(settings.SECRET_KEY.encode(), f"otp:{order_id}:{nonce}".encode(), hashlib.sha256).digest()
    return f"{int.from_bytes(d[:4], 'big') % 10**6:06d}"


def _nonce(order_id):
    return Order.objects.filter(order_id=order_id).values_list("otp_nonce", flat=True).first() or 0


def issue_otp(order_id):
    return otp_for(order_id, _nonce(order_id))


def verify_otp(otp, order_id, nonce=None):
    nonce = _nonce(order_id) if nonce is None else nonce
    return hmac.compare_digest(str(otp).encode(), otp_for(order_id, nonce).encode())


def otp_challenge(order_id, nonce):
    """What the phone downloads: a salted slow hash, so it can check the customer's OTP with NO signal."""
    salt = hashlib.sha256(f"salt:{settings.SECRET_KEY}:{order_id}:{nonce}".encode()).hexdigest()[:16]
    h = hashlib.pbkdf2_hmac("sha256", otp_for(order_id, nonce).encode(), salt.encode(), OTP_ITER).hex()
    return {"salt": salt, "iter": OTP_ITER, "hash": h}


def sms_text(order_id, otp):
    return (f"Your delivery code for {order_id} is {otp}. Give it to the delivery agent only when your "
            "order arrives. We do not store your phone number.")


def send_sms(phone, text):
    """Dev stub. Plug a real SMS provider in here (MSG91, Fast2SMS, Twilio). The number is never stored."""
    if not phone:
        return False
    print(f"[SMS to {phone}] {text}")
    return True


def manifest_for(device):
    """Today's route for one phone: undelivered orders + the offline OTP check data."""
    delivered = set(Event.objects.filter(type="DELIVERY").values_list("order_id", flat=True))
    rows = []
    for o in device.orders.exclude(order_id__in=delivered).order_by("created_at"):
        rows.append({"order_id": o.order_id, "village": o.village, "customer_ref": o.customer_ref,
                     "depot": o.depot, "item": o.item, "qty": o.qty, "amount_due": o.amount_due,
                     "otp": otp_challenge(o.order_id, o.otp_nonce)})
    return rows


# ---------- ingest: idempotent, order-independent, hash-chained ----------
def _clean(raw):
    try:
        eid, seq = uuid.UUID(str(raw["event_id"])), int(raw["seq"])
        etype, payload, ts = raw["type"], raw["payload"], parse_datetime(raw["client_ts"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return None, "malformed"
    if seq < 1 or etype not in REQUIRED or not isinstance(payload, dict) or ts is None:
        return None, "malformed"
    if not REQUIRED[etype] <= payload.keys():
        return None, "missing_fields"
    try:
        for k in NUMERIC & payload.keys():
            Decimal(str(payload[k]))
    except InvalidOperation:
        return None, "bad_number"
    if timezone.is_naive(ts):
        ts = ts.replace(tzinfo=datetime.timezone.utc)
    return {"event_id": eid, "seq": seq, "type": etype, "payload": dict(payload), "client_ts": ts}, None


@transaction.atomic
def ingest_batch(device, raw_events, local_max_seq=None):
    """Store each event at most once. Returns ids the device may safely delete from its outbox."""
    head, _ = LedgerHead.objects.select_for_update().get_or_create(pk=1)
    cleaned, rejected = [], []
    for raw in raw_events:
        c, err = _clean(raw)
        if err:
            rejected.append({"event_id": raw.get("event_id") if isinstance(raw, dict) else None, "reason": err})
        else:
            cleaned.append(c)
    cleaned.sort(key=lambda c: c["seq"])

    known_ids = set(Event.objects.filter(event_id__in=[c["event_id"] for c in cleaned]).values_list("event_id", flat=True))
    known_seqs = set(Event.objects.filter(device=device, seq__in=[c["seq"] for c in cleaned]).values_list("seq", flat=True))
    wanted = {str(c["payload"].get("order_id", ""))[:64] for c in cleaned}
    nonces = dict(Order.objects.filter(order_id__in=wanted).values_list("order_id", "otp_nonce"))

    acked, new, prev, otp_failed = [], [], head.last_hash, []
    seen_ids, seen_seqs = set(), set()
    for c in cleaned:
        if c["event_id"] in known_ids or c["event_id"] in seen_ids:
            acked.append(str(c["event_id"]))            # duplicate: harmless no-op
            continue
        if c["seq"] in known_seqs or c["seq"] in seen_seqs:
            rejected.append({"event_id": str(c["event_id"]), "reason": "seq_conflict"})
            continue
        p = c["payload"]
        oid = str(p.get("order_id", ""))[:64]
        qr_ok = c["type"] == "DELIVERY" and bool(p.get("qr_token")) and verify_qr(p["qr_token"], oid)
        otp_state = "none"
        if c["type"] == "DELIVERY":
            otp = p.pop("otp", None)                     # checked here, never written to the ledger
            if otp is not None:
                otp_state = "ok" if verify_otp(otp, oid, nonces.get(oid, 0)) else "wrong"
                if otp_state == "wrong":
                    otp_failed.append(str(c["event_id"]))
        h = _sha({"id": str(c["event_id"]), "dev": device.device_id, "seq": c["seq"], "type": c["type"],
                  "payload": p, "ts": c["client_ts"].isoformat()})
        prev = hashlib.sha256((prev + h).encode()).hexdigest()
        new.append(Event(device=device, order_id=oid, otp_state=otp_state, qr_verified=qr_ok,
                         content_hash=h, chain_hash=prev, **c))
        seen_ids.add(c["event_id"]); seen_seqs.add(c["seq"])
        acked.append(str(c["event_id"]))

    Event.objects.bulk_create(new)
    head.last_hash, head.count = prev, head.count + len(new)
    head.save()
    device.last_sync = timezone.now()
    if local_max_seq:
        device.reported_max_seq = max(device.reported_max_seq, int(local_max_seq))
    device.save(update_fields=["last_sync", "reported_max_seq"])
    return {"acked": acked, "new": len(new), "rejected": rejected, "otp_failed": otp_failed}


def verify_chain():
    """Recompute the whole chain. Returns (ok, first_bad_event_id)."""
    prev = "0" * 64
    for e in Event.objects.select_related("device").order_by("id").iterator():
        h = _sha({"id": str(e.event_id), "dev": e.device.device_id, "seq": e.seq, "type": e.type,
                  "payload": e.payload, "ts": e.client_ts.isoformat()})
        prev = hashlib.sha256((prev + h).encode()).hexdigest()
        if h != e.content_hash or prev != e.chain_hash:
            return False, e.id
    return True, None


# ---------- projections: pure functions of the event log ----------
def projections(include_orders=False):
    """Same events in => same answer out, whatever order or time they arrived."""
    stock = defaultdict(Decimal)
    orders = defaultdict(lambda: {"due": Decimal(0), "paid": Decimal(0), "delivered": False, "confirmed": False,
                                  "tries": 0, "failed_attempts": 0, "reason": ""})
    tanks, double_entry = {}, []
    for e in Event.objects.order_by("device_id", "seq").iterator():   # arrival-order independent
        p, d = e.payload, lambda k: Decimal(str(p[k]))
        if e.type == "RESTOCK":
            stock[(p["depot"], p["item"])] += d("qty")
        elif e.type == "DELIVERY":
            o = orders[p["order_id"]]
            o["tries"] += _int(p.get("otp_tries", 0)) + (1 if e.otp_state == "wrong" else 0)
            if o["delivered"]:                       # same order recorded twice -> alert, ignore effect
                double_entry.append({"order_id": p["order_id"], "event_id": str(e.event_id)})
                continue
            o["delivered"], o["confirmed"] = True, e.otp_state == "ok"
            if not o["confirmed"]:
                o["reason"] = str(p.get("no_otp_reason") or ("wrong_otp" if e.otp_state == "wrong" else "not_given"))
            o["due"] = d("amount_due")
            stock[(p["depot"], p["item"])] -= d("qty")
        elif e.type == "PAYMENT":
            orders[p["order_id"]]["paid"] += d("amount")
        elif e.type == "FAILED_ATTEMPT":
            orders[p["order_id"]]["failed_attempts"] += 1
        elif e.type == "SENSOR":
            tanks[(e.device_id, p["tank_id"])] = (p["tank_id"], d("level_pct"))   # later seq wins
    threshold = Decimal(str(getattr(settings, "TANK_ALERT_PCT", 20)))
    out = {
        "stock": {f"{dep}|{item}": q for (dep, item), q in sorted(stock.items())},
        "outstanding": sum((max(o["due"] - o["paid"], 0) for o in orders.values() if o["delivered"]), Decimal(0)),
        "unpaid_orders": sorted(k for k, o in orders.items() if o["delivered"] and o["paid"] < o["due"]),
        "unmatched_payments": sorted(k for k, o in orders.items() if o["paid"] and not o["delivered"]),
        "double_entry_alerts": double_entry,
        "unconfirmed_deliveries": [{"order_id": k, "reason": o["reason"]} for k, o in sorted(orders.items())
                                   if o["delivered"] and not o["confirmed"]],
        "otp_suspicious": [{"order_id": k, "tries": o["tries"]} for k, o in sorted(orders.items()) if o["tries"] >= 3],
        "postponed_orders": sorted(k for k, o in orders.items() if o["failed_attempts"] and not o["delivered"]),
        "tank_alerts": [{"tank_id": t, "level_pct": lvl} for t, lvl in tanks.values() if lvl < threshold],
    }
    if include_orders:
        out["order_states"] = dict(orders)
    return out


def orders_overview():
    states = projections(include_orders=True)["order_states"]
    rows = []
    for o in Order.objects.select_related("assigned_device").order_by("-created_at"):
        s = states.get(o.order_id)
        status = "dispatched"
        if s and s["delivered"]:
            status = "confirmed" if s["confirmed"] else "unconfirmed"
        elif s and s["failed_attempts"]:
            status = "postponed"
        rows.append({"order_id": o.order_id, "village": o.village, "customer_ref": o.customer_ref, "depot": o.depot,
                     "item": o.item, "qty": o.qty, "amount_due": o.amount_due, "paid": s["paid"] if s else 0,
                     "status": status, "tries": s["tries"] if s else 0, "reason": s["reason"] if s else "",
                     "device": o.assigned_device.device_id if o.assigned_device else None})
    return rows


def sync_status():
    """What is still pending: per-device gaps plus a 'complete as of' watermark."""
    devices = []
    for d in Device.objects.filter(is_active=True):
        seqs = list(d.events.order_by("seq").values_list("seq", flat=True))
        have, top = set(seqs), (seqs[-1] if seqs else 0)
        missing = [s for s in range(1, max(top, d.reported_max_seq) + 1) if s not in have]
        devices.append({
            "device_id": d.device_id, "kind": d.kind, "last_sync": d.last_sync,
            "received": len(seqs), "contiguous_upto": (missing[0] - 1) if missing else top,
            "pending_count": len(missing), "pending_sample": missing[:50],
        })
    never = any(x["last_sync"] is None for x in devices)
    return {
        "complete": bool(devices) and not never and all(x["pending_count"] == 0 for x in devices),
        "complete_as_of": None if never or not devices else min(x["last_sync"] for x in devices),
        "devices": devices,
    }
