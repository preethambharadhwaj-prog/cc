# Put this file at: ledger/management/commands/seed.py
import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from ledger import services
from ledger.models import Device, Order


class Command(BaseCommand):
    help = "Create a demo admin, device and order (safe to run on every start)"

    def handle(self, *a, **kw):
        User = get_user_model()
        user, pw = os.environ.get("ADMIN_USER", "admin"), os.environ.get("ADMIN_PASS")
        if pw and not User.objects.filter(username=user).exists():
            User.objects.create_superuser(user, "", pw)
        dev, _ = Device.objects.get_or_create(
            device_id="phone-1", defaults={"secret": os.environ.get("DEVICE_SECRET", "s3cret"), "kind": "phone"})
        order, _ = Order.objects.get_or_create(
            order_id="ORD-DEMO", defaults={"village": "Kollegal", "qty": 2, "amount_due": 1800, "assigned_device": dev})
        self.stdout.write(f"Demo order ORD-DEMO OTP: {services.otp_for(order.order_id, order.otp_nonce)}")
