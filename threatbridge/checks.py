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
    if settings.SECURE_HSTS_SECONDS < 31_536_000:
        messages.append(
            Warning(
                "HSTS is below one year; follow the documented staged rollout before preload.",
                id="threatbridge.W001",
            )
        )
    return messages
