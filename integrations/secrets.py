from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

SENSITIVE_KEY_PARTS = (
    "authorization",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "client_secret",
    "error",
    "exception",
    "headers",
    "message",
    "query",
    "response_body",
)

CONFIGURATION_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "headers",
        "password",
        "secret",
        "token",
    }
)
CURSOR_SECRET_KEYS = CONFIGURATION_SECRET_KEYS | {
    "access_token",
    "auth",
    "signature",
    "sig",
}
MAX_SECRET_FILE_BYTES = 64 * 1024


def _parsed_secret_value(raw: str) -> Mapping[str, Any]:
    value = raw.strip()
    if not value:
        raise ValueError("Secret value is empty")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"value": value}
    if isinstance(parsed, Mapping):
        return dict(parsed)
    return {"value": parsed}


def _read_secret_file(reference: str) -> Mapping[str, Any]:
    path = Path(reference.removeprefix("file:").strip())
    if not path.is_absolute():
        raise ValueError("Secret file reference must use an absolute path")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ValueError("Secret file could not be opened") from None
    with os.fdopen(descriptor, "rb") as secret_file:
        file_status = os.fstat(secret_file.fileno())
        if not stat.S_ISREG(file_status.st_mode):
            raise ValueError("Secret file must be a regular file")
        if stat.S_IMODE(file_status.st_mode) & 0o077:
            raise ValueError("Secret file must not grant group or other permissions")
        payload = secret_file.read(MAX_SECRET_FILE_BYTES + 1)
    if len(payload) > MAX_SECRET_FILE_BYTES:
        raise ValueError("Secret file exceeds the configured safety limit")
    try:
        return _parsed_secret_value(payload.decode("utf-8"))
    except UnicodeDecodeError:
        raise ValueError("Secret file must contain UTF-8 text") from None


def resolve_secret_reference(reference: str) -> Mapping[str, Any]:
    """Resolve environment- or file-backed secrets without persisting values.

    ``env:VARIABLE`` reads one variable. Its value may be a JSON object or a
    plain string. ``env://PREFIX`` reads all variables beginning with
    ``PREFIX_`` and returns lower-case keys, so ``OPENCTI_TOKEN`` becomes
    ``token``. ``file:/absolute/path`` reads a non-symlink regular file
    whose mode grants no group or other permissions. Vault or cloud-secret
    implementations can replace this function later without changing the
    adapter contract.
    """

    if not reference:
        return {}

    if reference.startswith("file:"):
        return _read_secret_file(reference)

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
        raise ValueError(
            "Unsupported secret reference. Use env:VARIABLE, env://PREFIX, "
            "or file:/absolute/path"
        )
    variable = reference.removeprefix("env:").strip()
    if not variable:
        raise ValueError("Secret environment variable name is empty")
    raw = os.getenv(variable)
    if raw is None:
        raise ValueError(f"Secret environment variable {variable} is not set")
    return _parsed_secret_value(raw)


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


def _configuration_key(value: Any) -> str:
    return str(value).strip().casefold().replace("-", "_")


def validate_non_secret_configuration(value: Any) -> None:
    """Reject credentials embedded in ordinary connector configuration."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if _configuration_key(key) in CONFIGURATION_SECRET_KEYS:
                raise ValueError(
                    "Integration credentials must use secret_reference, not configuration"
                )
            validate_non_secret_configuration(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            validate_non_secret_configuration(item)


def redacted_configuration(value: Any) -> Any:
    """Hide any legacy credential fields before rendering configuration."""

    if isinstance(value, Mapping):
        return {
            str(key): (
                "<redacted>"
                if _configuration_key(key) in CONFIGURATION_SECRET_KEYS
                else redacted_configuration(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redacted_configuration(item) for item in value]
    return value


def _secret_strings(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        result: set[str] = set()
        for item in value.values():
            result.update(_secret_strings(item))
        return result
    if isinstance(value, (list, tuple, set)):
        result = set()
        for item in value:
            result.update(_secret_strings(item))
        return result
    text = str(value)
    return {text} if len(text) >= 4 else set()


def _contains_known_secret(value: Any, secret_values: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_known_secret(item, secret_values) for item in value.values()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_known_secret(item, secret_values) for item in value)
    text = str(value)
    return any(secret in text for secret in secret_values)


def validate_safe_cursor(
    value: Any,
    *,
    resolved_secrets: Mapping[str, Any] | None = None,
) -> None:
    """Reject connector cursors that could persist credential material."""

    if _contains_known_secret(value, _secret_strings(resolved_secrets or {})):
        raise ValueError("Connector cursor contains sensitive material and cannot be stored")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if _configuration_key(key) in CURSOR_SECRET_KEYS:
                raise ValueError(
                    "Connector cursor contains sensitive material and cannot be stored"
                )
            validate_safe_cursor(item)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            validate_safe_cursor(item)
        return
    text = str(value)
    if text.startswith(("http://", "https://")):
        sensitive_query = any(
            _configuration_key(key) in CURSOR_SECRET_KEYS
            for key, _query_value in parse_qsl(urlsplit(text).query, keep_blank_values=True)
        )
        if sensitive_query:
            raise ValueError(
                "Connector cursor contains sensitive material and cannot be stored"
            )


def _redact_known_values(value: Any, secret_values: set[str]) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _redact_known_values(item, secret_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_known_values(item, secret_values) for item in value]
    text = str(value)
    for secret in secret_values:
        if secret in text:
            return "<redacted>"
    return value


def redacted_result(
    value: Mapping[str, Any],
    *,
    resolved_secrets: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Redact connector diagnostics before storing or returning them."""

    result = safe_excerpt(value)
    result = _redact_known_values(result, _secret_strings(resolved_secrets or {}))
    return dict(result) if isinstance(result, Mapping) else {"result": result}


def sanitized_connector_error(exc: BaseException) -> str:
    """Describe a connector failure without persisting vendor-controlled text."""

    return f"{type(exc).__name__}: connector operation failed"
