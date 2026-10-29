from django.db import models


class Device(models.Model):
    """A phone, depot scale or tank sensor that uploads events."""
    class Kind(models.TextChoices):
        PHONE = "phone"
        SCALE = "scale"
        SENSOR = "sensor"

    device_id = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120, blank=True)
    kind = models.CharField(max_length=10, choices=Kind.choices, default=Kind.PHONE)
    secret = models.CharField(max_length=128)  # per-device HMAC key (keep in a secrets store in prod)
    is_active = models.BooleanField(default=True)   # False = revoked (lost phone)
    last_sync = models.DateTimeField(null=True, blank=True)
    reported_max_seq = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.device_id


class Order(models.Model):
    """What the office dispatches. No phone number or name is stored (DPDP data minimisation)."""
    order_id = models.CharField(max_length=64, unique=True)
    customer_ref = models.CharField(max_length=60, blank=True)   # internal reference only
    village = models.CharField(max_length=80, blank=True)
    depot = models.CharField(max_length=40, default="D1")
    item = models.CharField(max_length=60, default="LPG-14kg")
    qty = models.PositiveIntegerField(default=1)
    amount_due = models.DecimalField(max_digits=10, decimal_places=2)
    assigned_device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name="orders")
    otp_nonce = models.PositiveIntegerField(default=0)           # bump to invalidate the old OTP
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.order_id


class LedgerHead(models.Model):
    """Singleton row holding the tip of the tamper-evident hash chain."""
    last_hash = models.CharField(max_length=64, default="0" * 64)
    count = models.PositiveBigIntegerField(default=0)


class Event(models.Model):
    """Append-only source of truth. Never updated or deleted by the app."""
    class Type(models.TextChoices):
        RESTOCK = "RESTOCK"
        DELIVERY = "DELIVERY"
        PAYMENT = "PAYMENT"
        SENSOR = "SENSOR"
        FAILED_ATTEMPT = "FAILED_ATTEMPT"

    event_id = models.UUIDField(unique=True)            # idempotency key (made on the device)
    device = models.ForeignKey(Device, on_delete=models.PROTECT, related_name="events")
    seq = models.PositiveIntegerField()                  # per-device monotonic counter
    type = models.CharField(max_length=16, choices=Type.choices)
    order_id = models.CharField(max_length=64, blank=True, db_index=True)
    payload = models.JSONField()
    client_ts = models.DateTimeField()                   # device clock: informational only
    received_at = models.DateTimeField(auto_now_add=True)
    qr_verified = models.BooleanField(default=False)
    otp_state = models.CharField(max_length=5, default="none")   # ok | wrong | none
    content_hash = models.CharField(max_length=64)
    chain_hash = models.CharField(max_length=64)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["device", "seq"], name="uniq_device_seq")]
        indexes = [models.Index(fields=["type"])]
