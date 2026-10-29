from django.contrib import admin
from django.shortcuts import redirect
from django.urls import path, include

urlpatterns = [
    path("", lambda request: redirect("/api/dashboard/")),
    path("admin/", admin.site.urls),
    path("api/", include("ledger.urls")),
]