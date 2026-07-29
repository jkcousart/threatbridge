from django.conf import settings
from django.core.checks import Error, Tags, Warning, register


@register(Tags.security, deploy=True)
def threatbridge_deployment_checks(app_configs, **kwargs):
    del app_configs, kwargs
    messages = []
    if settings.DEBUG:
        return messages
    if settings.DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3":
        messages.append(
            Error(
                "Production must use an explicitly configured PostgreSQL database.",
                id="threatbridge.E001",
            )
        )
    if not settings.THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS:
        messages.append(
            Error(
                "Production requires an exact outbound-host allow-list.",
                id="threatbridge.E002",
            )
        )
    handlers = getattr(settings, "LOGGING", {}).get("handlers", {})
    if not handlers or not all(
        "redact_sensitive_data" in handler.get("filters", ()) for handler in handlers.values()
    ):
        messages.append(
            Error(
                "Every logging handler must apply the redact_sensitive_data filter.",
                id="threatbridge.E003",
            )
        )
    throttle_rates = getattr(settings, "REST_FRAMEWORK", {}).get("DEFAULT_THROTTLE_RATES", {})
    if not throttle_rates.get("anon") or not throttle_rates.get("user"):
        messages.append(
            Error(
                "Production requires anonymous and authenticated API throttle rates.",
                id="threatbridge.E004",
            )
        )
    if settings.SECURE_HSTS_SECONDS < 31_536_000:
        messages.append(
            Warning(
                "HSTS is below one year; follow the documented staged rollout before preload.",
                id="threatbridge.W001",
            )
        )
    if getattr(settings, "SECURE_PROXY_SSL_HEADER", None):
        messages.append(
            Warning(
                "X-Forwarded-Proto is trusted. Confirm the reverse proxy overwrites that "
                "header and that the container port is unreachable from clients.",
                id="threatbridge.W002",
            )
        )
    return messages
