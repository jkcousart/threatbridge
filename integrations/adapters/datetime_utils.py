from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from django.utils import timezone
from django.utils.dateparse import parse_datetime


def parse_source_datetime(value: Any) -> datetime | None:
    """Parse an integration timestamp and always return an aware datetime.

    Most vendor APIs use ISO 8601 and UTC. Some exports omit an explicit offset;
    ThreatBridge treats those timestamps as UTC instead of inheriting the server's
    local timezone, which keeps evidence ordering deterministic across deployments.
    """

    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        result = value
    else:
        result = parse_datetime(str(value).strip().replace("Z", "+00:00"))
    if result is None:
        return None
    if timezone.is_naive(result):
        return timezone.make_aware(result, UTC)
    return result
