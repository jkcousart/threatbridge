from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from django.conf import settings

ARCHIVE_SIGNATURES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
)


def configured_limit(name: str, default: int) -> int:
    value = int(getattr(settings, name, default))
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def validate_upload_name(name: str) -> str:
    raw = str(name or "")
    normalized = raw.replace("\\", "/")
    parts = normalized.split("/")
    if not raw or len(parts) != 1 or parts[0] in {".", ".."} or ".." in parts:
        raise ValueError("Upload filename must not contain a path")
    return raw


def validate_uncompressed_content(content: bytes) -> None:
    if b"\x00" in content:
        raise ValueError("Upload contains a null byte")
    if any(content.startswith(signature) for signature in ARCHIVE_SIGNATURES):
        raise ValueError("Archive and compressed uploads are not supported")


def validate_json_value(value: Any, *, depth: int = 0) -> None:
    max_depth = configured_limit("THREATBRIDGE_MAX_JSON_DEPTH", 20)
    if depth > max_depth:
        raise ValueError(f"JSON nesting exceeds the configured depth limit of {max_depth}")

    max_fields = configured_limit("THREATBRIDGE_MAX_OBJECT_FIELDS", 500)
    max_name = configured_limit("THREATBRIDGE_MAX_FIELD_NAME_LENGTH", 200)
    max_scalar = configured_limit("THREATBRIDGE_MAX_SCALAR_LENGTH", 100_000)
    if isinstance(value, Mapping):
        if len(value) > max_fields:
            raise ValueError(
                f"JSON object contains more than the configured {max_fields}-field limit"
            )
        for key, item in value.items():
            if len(str(key)) > max_name:
                raise ValueError(
                    f"JSON field name exceeds the configured {max_name}-character limit"
                )
            validate_json_value(item, depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            validate_json_value(item, depth=depth + 1)
    elif isinstance(value, str) and len(value) > max_scalar:
        raise ValueError(
            f"JSON string exceeds the configured {max_scalar}-character limit"
        )


def validate_csv_shape(fields: Sequence[str], row: Mapping[str, Any] | None = None) -> None:
    max_columns = configured_limit("THREATBRIDGE_MAX_CSV_COLUMNS", 500)
    max_name = configured_limit("THREATBRIDGE_MAX_FIELD_NAME_LENGTH", 200)
    max_scalar = configured_limit("THREATBRIDGE_MAX_CSV_FIELD_LENGTH", 100_000)
    if len(fields) > max_columns:
        raise ValueError(f"CSV contains more than the configured {max_columns}-column limit")
    if any(len(str(field)) > max_name for field in fields):
        raise ValueError(
            f"CSV field name exceeds the configured {max_name}-character limit"
        )
    if row and any(len(str(value or "")) > max_scalar for value in row.values()):
        raise ValueError(
            f"CSV field exceeds the configured {max_scalar}-character limit"
        )


def read_bounded_path(path: Path) -> bytes:
    maximum = configured_limit("THREATBRIDGE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)
    with path.open("rb") as handle:
        content = handle.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError(f"File is too large. Maximum upload size is {maximum:,} bytes")
    validate_uncompressed_content(content)
    return content
