from __future__ import annotations

import os

from django.core.exceptions import ImproperlyConfigured

from threatbridge.startup_audit import record_production_configuration_failure

DEBUG_VARIABLE = "DJANGO_DEBUG"


def require_explicit_debug_configuration() -> None:
    """Refuse to serve unless DJANGO_DEBUG was set deliberately.

    ``threatbridge.settings`` defaults DEBUG to true so ``manage.py`` and the test
    suite stay usable without configuration. That default must never reach a WSGI or
    ASGI server, because a true DEBUG value also skips every production configuration
    check. Both application entry points therefore demand an explicit value.
    """

    if os.getenv(DEBUG_VARIABLE) is None:
        record_production_configuration_failure(DEBUG_VARIABLE)
        raise ImproperlyConfigured(
            f"{DEBUG_VARIABLE} must be set explicitly to 'true' or 'false' before "
            "serving ThreatBridge through a WSGI or ASGI server"
        )
