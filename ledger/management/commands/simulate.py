"""python manage.py simulate  -> replays gapped, duplicated, shuffled, bursty streams and checks the totals."""
import hashlib
import random
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone as tz
from decimal import Decimal

from django.core.management.base import BaseCommand

from ledger import services
from ledger.models import Device, Event, LedgerHead, Order

ITEM, DEPOTS = "LPG-14kg", ["D1", "D2"]


class Command(BaseCommand):
    help = "Simulate unreliable field sync and compare against ground truth"

    def add_arguments(self, p):
        p.add_argument("--orders", type=int, default=300)
        p.add_argument("--seed", type=int, default=42)
        p.add_argument("--batch", type=int, default=40)

    def handle(self, *a, orders, seed, batch, **kw):
        rng = random.Random(seed)
        Event.objects.all().delete(); Order.objects.all().delete(); Device.objects.all().delete(); LedgerHead.objects.all().delete()
        devs = [Device.objects.create(device_id=f"phone-{i}", secret="s3cret") for i in range(3)]
        devs.append(Device.objects.create(device_id="sensor-1", kind="sensor", secret="s3cret"))
        stream, seq = {d.pk: [] for d in devs}, defaultdict(int)
        base = datetime(2026, 10, 28, 6, 0, tzinfo=tz.utc)

        def emit(dev, etype, payload):
            seq[dev.pk] += 1
            drift = timedelta(minutes=rng.randint(-15, 15))        # unreliable device clock
            stream[dev.pk].append({"event_id": str(uuid.uuid4()), "seq": seq[dev.pk], "type": etype,
                                   "payload": payload, "client_ts": (base + drift).isoformat()})

        # ground truth is tracked independently of the server code
        stock, due, paid = defaultdict(Decimal), Decimal(0), Decimal(0)
        for dep in DEPOTS:
            emit(devs[0], "RESTOCK", {"depot": dep, "item": ITEM, "qty": 500}); stock[f"{dep}|{ITEM}"] += 500
        for i in range(orders):
            dev, dep, qty = rng.choice(devs[:3]), rng.choice(DEPOTS), rng.randint(1, 3)
            amt, oid = qty * 900, f"ORD-{i}"
            emit(dev, "DELIVERY", {"order_id": oid, "depot": dep, "item": ITEM, "qty": qty, "amount_due": amt,
                                   "qr_token": services.issue_qr(oid), "otp": services.issue_otp(oid)})
            stock[f"{dep}|{ITEM}"] -= qty; due += amt
            if rng.random() < 0.8:
                pay = amt if rng.random() < 0.7 else amt // 2
                emit(rng.choice(devs[:3]), "PAYMENT", {"order_id": oid, "amount": pay}); paid += pay
        for lvl in (80, 55, 30, 15):
            emit(devs[3], "SENSOR", {"tank_id": "T1", "level_pct": lvl})
        truth_out = due - paid

        # a delivery whose customer gave a WRONG otp, and one recorded with no otp (customer had no SMS)
        emit(devs[1], "DELIVERY", {"order_id": "ORD-WRONG", "depot": "D1", "item": ITEM, "qty": 1, "amount_due": 900, "otp": "000000x"})
        emit(devs[2], "DELIVERY", {"order_id": "ORD-NOSMS", "depot": "D1", "item": ITEM, "qty": 1, "amount_due": 900, "no_otp_reason": "no_sms"})
        stock[f"D1|{ITEM}"] -= 2; due += 1800; truth_out += 1800
        # a customer who was not home
        emit(devs[0], "FAILED_ATTEMPT", {"order_id": "ORD-LATER", "reason": "customer_absent"})
        # an agent accidentally records one delivery twice (new event id): alert, totals unchanged
        dup_src = next(e for e in stream[devs[0].pk] if e["type"] == "DELIVERY")
        emit(devs[0], "DELIVERY", dup_src["payload"])

        def send(dev, events):
            events = events[:]; rng.shuffle(events)
            events += rng.sample(events, k=len(events) // 3)           # 33% duplicates
            rng.shuffle(events)
            for i in range(0, len(events), batch):
                services.ingest_batch(dev, events[i:i + batch], local_max_seq=seq[dev.pk])
            return len(events)

        # phase 1: phones were offline for part of the day, 20% of events still on the device
        held = {}
        for d in devs:
            evs = stream[d.pk]; held[d.pk] = [e for e in evs if rng.random() < 0.2]
            send(d, [e for e in evs if e not in held[d.pk]])
        st = services.sync_status()
        self.stdout.write(f"Phase 1: complete={st['complete']} pending={sum(x['pending_count'] for x in st['devices'])}")

        # phase 2: connectivity returns, every device dumps everything at once (worst-case burst + replay of old data)
        t0, sent = time.perf_counter(), 0
        for d in devs:
            sent += send(d, held[d.pk] + stream[d.pk])
        pr = services.projections(); st = services.sync_status()
        dt = time.perf_counter() - t0
        ok_chain, _ = services.verify_chain()
        self.stdout.write(f"Burst: {sent} events (incl. replays) in {dt:.2f}s = {sent / dt:.0f} events/s; "
                          f"consistent {dt:.2f}s after reconnect")

        # route manifest + offline OTP data
        for oid in ("ORD-0", "ORD-1", "ORD-X1", "ORD-X2"):
            Order.objects.create(order_id=oid, village="Kollegal", amount_due=900, assigned_device=devs[0])
        before = {m["order_id"]: m for m in services.manifest_for(devs[0])}
        o = Order.objects.get(order_id="ORD-X1"); o.otp_nonce += 1; o.save()
        after = {m["order_id"]: m for m in services.manifest_for(devs[0])}
        ch = after["ORD-X1"]["otp"]
        phone_hash = hashlib.pbkdf2_hmac("sha256", services.otp_for("ORD-X1", 1).encode(), ch["salt"].encode(), ch["iter"]).hex()

        by_order = {x["order_id"]: x["reason"] for x in pr["unconfirmed_deliveries"]}
        checks = {
            "no duplicate rows (events == generated)": Event.objects.count() == sum(len(v) for v in stream.values()),
            "stock matches ground truth": dict(pr["stock"]) == dict(stock),
            "outstanding collections match": pr["outstanding"] == truth_out,
            "double-entry alert raised": len(pr["double_entry_alerts"]) == 1,
            "low-tank alert raised": [a["tank_id"] for a in pr["tank_alerts"]] == ["T1"],
            "only the 2 bad deliveries lack OTP confirmation": by_order == {"ORD-WRONG": "wrong_otp", "ORD-NOSMS": "no_sms"},
            "postponed order listed": pr["postponed_orders"] == ["ORD-LATER"],
            "route lists only undelivered orders": set(before) == {"ORD-X1", "ORD-X2"},
            "new OTP code invalidates the old one": services.verify_otp(services.otp_for("ORD-X1", 1), "ORD-X1")
                                                    and not services.verify_otp(services.otp_for("ORD-X1", 0), "ORD-X1"),
            "phone-side hash (offline check) matches": before["ORD-X1"]["otp"]["hash"] != ch["hash"] and phone_hash == ch["hash"],
            "nothing pending": st["complete"],
            "hash chain intact": ok_chain,
        }
        for name, passed in checks.items():
            self.stdout.write(f"  [{'PASS' if passed else 'FAIL'}] {name}")
