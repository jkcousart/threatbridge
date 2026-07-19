from django.contrib import admin
from django.db import connection
from django.http import JsonResponse
from django.urls import include, path


def healthz(_request):
    return JsonResponse({"status": "ok", "service": "threatbridge"})


def readyz(_request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as exc:
        return JsonResponse(
            {"status": "not_ready", "service": "threatbridge", "error": str(exc)},
            status=503,
        )
    return JsonResponse({"status": "ready", "service": "threatbridge"})


urlpatterns = [
    path("healthz", healthz, name="healthz"),
    path("readyz", readyz, name="readyz"),
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("api/", include("integrations.urls")),
    path("api/catalog/", include("catalog.urls")),
    path("api-auth/", include("rest_framework.urls")),
    path("", include("catalog.web_urls")),
]
