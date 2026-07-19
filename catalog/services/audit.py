from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from catalog.models import SecurityAuditEvent

SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "client_secret",
    "raw",
    "uploaded_file",
    "request_headers",
    "response_body",
    "exception",
)


def _actor_fields(actor: Any) -> tuple[Any | None, str]:
    if not actor or not getattr(actor, "is_authenticated", False):
        return None, "system"
    label = str(actor.get_username() or actor.pk)[:255]
    return actor, label


def safe_audit_metadata(value: Any, *, depth: int = 0) -> Any:
    """Return bounded structured metadata with secret-bearing fields removed."""

    if depth > 4:
        return "<truncated>"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:50]:
            key_text = str(key)[:100]
            if any(part in key_text.casefold() for part in SENSITIVE_KEY_PARTS):
                result[key_text] = "<redacted>"
            else:
                result[key_text] = safe_audit_metadata(item, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [safe_audit_metadata(item, depth=depth + 1) for item in value[:50]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if "bearer " in text.casefold():
        return "<redacted>"
    return text[:500]


def record_security_event(
    *,
    event_type: str,
    origin: str,
    outcome: str,
    actor: Any = None,
    target_type: str = "",
    target_identifier: str | int = "",
    metadata: Mapping[str, Any] | None = None,
) -> SecurityAuditEvent:
    event_actor, actor_label = _actor_fields(actor)
    return SecurityAuditEvent.objects.create(
        actor=event_actor,
        actor_label=actor_label,
        origin=str(origin)[:255],
        event_type=str(event_type)[:100],
        target_type=str(target_type)[:100],
        target_identifier=str(target_identifier)[:255],
        outcome=str(outcome)[:32],
        metadata=safe_audit_metadata(metadata or {}),
    )
