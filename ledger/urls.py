from django.urls import path
from . import views

urlpatterns = [
    path("sync/", views.sync),              # devices upload batches
    path("manifest/", views.manifest),      # devices download today's route + offline OTP data
    path("report/", views.report),          # stock, collections, alerts, pending status
    path("pending/", views.pending),
    path("audit/", views.audit),            # verify the hash chain
    path("orders/", views.orders),          # list / create orders (staff)
    path("otp/", views.issue_otp),          # resend or regenerate delivery OTP
    path("revoke/", views.revoke),          # block a lost phone
    path("qr/", views.issue_qr),
    path("export/", views.export_csv),      # CSV of the whole ledger
    path("sw.js", views.service_worker),    # offline cache for the agent page
    path("agent/", views.agent_page),       # /api/agent/
    path("dashboard/", views.dashboard_page),  # /api/dashboard/
]
