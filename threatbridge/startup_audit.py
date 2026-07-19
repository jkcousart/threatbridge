from __future__ import annotations

import json
import logging


def record_production_configuration_failure(setting_name: str) -> None:
    """Emit a safe structured event when the database-backed audit service cannot start."""

    event = {
        "actor": None,
        "event_type": "production_configuration.failed",
        "origin": "startup:settings",
        "outcome": "failed",
        "target_identifier": str(setting_name)[:100],
        "target_type": "setting",
    }
    logging.getLogger("threatbridge.security").critical(
        "ThreatBridge security event %s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )
