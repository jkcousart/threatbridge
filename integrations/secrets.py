from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

SENSITIVE_KEY_PARTS = (
    "authorization",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "client_secret",
)


def resolve_secret_reference(reference: str) -> Mapping[str, Any]:
    """Resolve environment-backed secrets without persisting their values.

    ``env:VARIABLE`` reads one variable. Its value may be a JSON object or a
    plain string. ``env://PREFIX`` reads all variables beginning with
    ``PREFIX_`` and returns lower-case keys, so ``DEFENDER_CLIENT_ID`` becomes
    ``client_id``. Vault or cloud-secret implementations can replace this
    function later without changing the adapter contract.
    """

    if not reference:
        return {}

    if reference.startswith("env://"):
        prefix = reference.removeprefix("env://").strip().upper().rstrip("_")
        if not prefix:
            raise ValueError("Secret environment prefix is empty")
        marker = f"{prefix}_"
        values = {
            key.removeprefix(marker).lower(): value
            for key, value in os.environ.items()
            if key.startswith(marker)
        }
        if not values:
            raise ValueError(f"No environment variables were found for prefix {prefix}")
        return values

    if not reference.startswith("env:"):
        raise ValueError("Unsupported secret reference. Use env:VARIABLE or env://PREFIX")
    variable = reference.removeprefix("env:").strip()
    if not variable:
        raise ValueError("Secret environment variable name is empty")
    raw = os.getenv(variable)
    if raw is None:
        raise ValueError(f"Secret environment variable {variable} is not set")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"value": raw}
    if isinstance(parsed, Mapping):
        return dict(parsed)
    return {"value": parsed}


def safe_excerpt(value: Any, *, max_text: int = 500, depth: int = 0) -> Any:
    """Return a bounded, recursively redacted representation for logs and APIs."""

    if depth > 3:
        return "<truncated>"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:30]:
            key_text = str(key)
            if any(part in key_text.casefold() for part in SENSITIVE_KEY_PARTS):
                result[key_text] = "<redacted>"
            else:
                result[key_text] = safe_excerpt(item, max_text=max_text, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [
            safe_excerpt(item, max_text=max_text, depth=depth + 1)
            for item in value[:20]
        ]
    text = str(value)
    return text if len(text) <= max_text else f"{text[:max_text]}...<truncated>"


def redacted_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Redact connector diagnostics before storing or returning them."""

    result = safe_excerpt(value)
    return dict(result) if isinstance(result, Mapping) else {"result": result}
