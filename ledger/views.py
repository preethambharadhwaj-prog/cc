import csv
import hashlib
import hmac
import json
import uuid
from decimal import Decimal, InvalidOperation

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import services
from .models import Device, Event, Order


def _json(data, status=200):
    return JsonResponse(data, status=status, encoder=DjangoJSONEncoder, safe=False)


def _body(request):
    try:
        d = json.loads(request.body or "{}")
        return d if isinstance(d, dict) else None
    except ValueError:
        return None


def _device_auth(request):
    """Devices sign the raw body: X-Device-Id + X-Signature (hex HMAC-SHA256). Returns (device, status)."""
    device = Device.objects.filter(device_id=request.headers.get("X-Device-Id", "")).first()
    if not device:
        return None, 401
    expected = hmac.new(device.secret.encode(), request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Signature", "")):
        return None, 401
    return (device, 200) if device.is_active else (None, 403)      # 403 = revoked (lost phone)


def _denied(code):
    return _json({"error": "revoked" if code == 403 else "unauthorized"}, code)


def _staff_only(view):
    def wrapped(request, *a, **kw):
        if not request.user.is_staff:
            return _json({"error": "staff only"}, 403)
        return view(request, *a, **kw)
    return wrapped


# ---------- device API ----------
@csrf_exempt
@require_POST
def sync(request):
    device, code = _device_auth(request)
    if not device:
        return _denied(code)
    body = _body(request)
    if body is None or not isinstance(body.get("events"), list):
        return _json({"error": "bad request"}, 400)
    if len(body["events"]) > getattr(settings, "MAX_BATCH", 1000):
        return _json({"error": "batch too large, split it"}, 413)
    return _json(services.ingest_batch(device, body["events"], body.get("local_max_seq")))


@csrf_exempt
@require_POST
def manifest(request):
    """The phone downloads its route (with offline OTP check data) while it still has signal."""
    device, code = _device_auth(request)
    if not device:
        return _denied(code)
    return _json({"orders": services.manifest_for(device), "server_time": timezone.now()})


# ---------- staff API ----------
@require_GET
@_staff_only
def report(request):
    return _json({"status": services.sync_status(), **services.projections()})


@require_GET
@_staff_only
def pending(request):
    return _json(services.sync_status())


@require_GET
@_staff_only
def audit(request):
    ok, bad = services.verify_chain()
    return _json({"chain_ok": ok, "first_bad_event": bad, "events": Event.objects.count()})


@require_http_methods(["GET", "POST"])
@_staff_only
def orders(request):
    if request.method == "GET":
        return _json({"orders": services.orders_overview()})
    d = _body(request)
    if d is None:
        return _json({"error": "bad request"}, 400)
    try:
        qty, due = int(d["qty"]), Decimal(str(d["amount_due"]))
        assert qty > 0 and due >= 0
    except (KeyError, ValueError, InvalidOperation, AssertionError):
        return _json({"error": "quantity and amount are required"}, 400)
    order_id = str(d.get("order_id") or "").strip()[:64] or f"ORD-{uuid.uuid4().hex[:6].upper()}"
    if Order.objects.filter(order_id=order_id).exists():
        return _json({"error": "order id already exists"}, 409)
    dev = Device.objects.filter(device_id=d.get("assigned_device")).first() if d.get("assigned_device") else None
    o = Order.objects.create(order_id=order_id, customer_ref=str(d.get("customer_ref") or "")[:60],
                             village=str(d.get("village") or "")[:80], depot=str(d.get("depot") or "D1")[:40],
                             item=str(d.get("item") or "LPG-14kg")[:60], qty=qty, amount_due=due, assigned_device=dev)
    otp = services.otp_for(o.order_id, o.otp_nonce)
    sent = services.send_sms(d.get("phone"), services.sms_text(o.order_id, otp))
    return _json({"order_id": o.order_id, "sms_sent": sent, "otp": otp if settings.DEBUG else None}, 201)


@require_POST
@_staff_only
def issue_otp(request):
    """Resend the delivery OTP, or issue a fresh one (the old code stops working)."""
    d = _body(request) or {}
    order_id = str(d.get("order_id") or "").strip()
    if not order_id:
        return _json({"error": "order_id required"}, 400)
    o = Order.objects.filter(order_id=order_id).first()
    if o and d.get("regenerate"):
        o.otp_nonce += 1
        o.save(update_fields=["otp_nonce"])
    otp = services.otp_for(order_id, o.otp_nonce if o else 0)
    sent = services.send_sms(d.get("phone"), services.sms_text(order_id, otp))
    return _json({"order_id": order_id, "sms_sent": sent, "otp": otp if settings.DEBUG else None})


@require_POST
@_staff_only
def revoke(request):
    """Lost or stolen phone: block it. The phone wipes itself the next time it reaches the server."""
    d = _body(request) or {}
    n = Device.objects.filter(device_id=d.get("device_id")).update(is_active=False)
    return _json({"revoked": n})


@require_POST
@_staff_only
def issue_qr(request):
    order_id = (_body(request) or {}).get("order_id")
    if not order_id:
        return _json({"error": "order_id required"}, 400)
    return _json({"order_id": order_id, "qr_token": services.issue_qr(order_id)})


@require_GET
@_staff_only
def export_csv(request):
    """Auditable export of the full ledger."""
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="ledger.csv"'
    w = csv.writer(resp)
    w.writerow(["id", "device", "seq", "type", "order_id", "payload", "client_ts", "received_at",
                "otp_state", "qr_verified", "chain_hash"])
    for e in Event.objects.select_related("device").order_by("id").iterator():
        w.writerow([e.id, e.device.device_id, e.seq, e.type, e.order_id, json.dumps(e.payload, sort_keys=True),
                    e.client_ts.isoformat(), e.received_at.isoformat(), e.otp_state, e.qr_verified, e.chain_hash])
    return resp


# ---------- pages ----------
SW_JS = """const C = 'agent-v1', PAGE = location.pathname.replace(/sw\\.js$/, 'agent/');
self.addEventListener('install', e => e.waitUntil(caches.open(C).then(c => c.add(PAGE)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(clients.claim()));
self.addEventListener('fetch', e => {
  if (new URL(e.request.url).pathname !== PAGE) return;
  e.respondWith(fetch(e.request).then(r => { const cp = r.clone(); caches.open(C).then(c => c.put(PAGE, cp)); return r; })
    .catch(() => caches.match(PAGE)));
});
"""


def service_worker(request):
    """Caches the agent page so it opens with no signal at all."""
    return HttpResponse(SW_JS, content_type="application/javascript")


def agent_page(request):
    return render(request, "ledger/agent.html")


@staff_member_required
@ensure_csrf_cookie
def dashboard_page(request):
    return render(request, "ledger/dashboard.html")
