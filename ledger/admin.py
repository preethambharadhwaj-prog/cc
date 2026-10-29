from django.contrib import admin
from .models import Device, Event, Order

admin.site.register(Device)
admin.site.register(Order)


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("device", "seq", "type", "order_id", "otp_state", "client_ts", "received_at")
    list_filter = ("type", "device", "otp_state")

    # append-only: no edits or deletes through the admin either
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
    def has_add_permission(self, request): return False
