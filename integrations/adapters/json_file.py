from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from django.conf import settings

from integrations.import_limits import (
    configured_limit,
    read_bounded_path,
    validate_json_value,
)

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime

COMMON_RECORD_KEYS = (
    "records",
    "items",
    "results",
    "objects",
    "reports",
    "assets",
    "devices",
    "findings",
    "vulnerabilities",
    "software",
    "detections",
    "rules",
    "tests",
    "data",
)
COMMON_RECORD_PARENTS = ("data", "response", "payload")


class JsonFileAdapter(IntegrationAdapter):
    adapter_key = "json-file"
    display_name = "Generic JSON/JSONL import"
    description = (
        "Imports field-mapped records or mixed ThreatBridge envelopes from JSON or JSON Lines."
    )
    supported_object_types = (
        "asset",
        "software_installation",
        "vulnerability",
        "vulnerability_finding",
        "attack_technique",
        "detection_rule",
        "telemetry_source",
        "validation_test",
        "validation_result",
        "threat_report",
    )
    configuration_schema = {
        "required": ["path"],
        "properties": {
            "path": {"type": "string"},
            "format": {"enum": ["json", "jsonl"]},
            "records_key": {"type": "string"},
            "object_type": {"type": "string"},
            "id_fields": {"type": "array"},
            "field_map": {"type": "object"},
            "envelope": {"type": "boolean"},
            "passthrough_unmapped": {"type": "boolean"},
            "skip_unchanged": {"type": "boolean"},
        },
    }
    configuration_example = {
        "path": "incoming/assets.json",
        "format": "json",
        "records_key": "records",
        "object_type": "asset",
        "id_fields": ["device.id"],
        "field_map": {
            "device.id": "asset_external_id",
            "device.name": "hostname",
            "device.platform": "os_platform",
        },
        "passthrough_unmapped": True,
    }

    def _path(self, context: SyncContext) -> Path:
        configured = str(context.configuration.get("path", "")).strip()
        if not configured:
            raise ValueError("JSON adapter requires configuration.path")
        base = Path(settings.THREATBRIDGE_DATA_DIR).resolve()
        candidate = (base / configured).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValueError("JSON path must remain inside THREATBRIDGE_DATA_DIR")
        return candidate

    @staticmethod
    def _lookup(value: Any, path: str, default: Any = None) -> Any:
        if not path:
            return default
        current = value
        for segment in path.split("."):
            if isinstance(current, Mapping):
                if segment not in current:
                    return default
                current = current[segment]
            elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
                try:
                    current = current[int(segment)]
                except (ValueError, IndexError):
                    return default
            else:
                return default
        return current

    @classmethod
    def _resolve_records(cls, payload: Any, records_key: str) -> list[Mapping[str, Any]]:
        if records_key:
            payload = cls._lookup(payload, records_key, default=None)
            if payload is None:
                raise ValueError(f"JSON records_key was not found: {records_key}")
        elif isinstance(payload, Mapping):
            resolved = False
            for key in COMMON_RECORD_KEYS:
                if isinstance(payload.get(key), list):
                    payload = payload[key]
                    resolved = True
                    break
            if not resolved:
                for parent_key in COMMON_RECORD_PARENTS:
                    parent = payload.get(parent_key)
                    if not isinstance(parent, Mapping):
                        continue
                    for key in COMMON_RECORD_KEYS:
                        if isinstance(parent.get(key), list):
                            payload = parent[key]
                            resolved = True
                            break
                    if resolved:
                        break
        if isinstance(payload, Mapping):
            records: list[Any] = [payload]
        elif isinstance(payload, list):
            records = payload
        else:
            raise ValueError("JSON payload must resolve to an object or array")
        if not all(isinstance(record, Mapping) for record in records):
            raise ValueError("All JSON records must be objects")
        return [dict(record) for record in records]

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        path = self._path(context)
        return {
            "ok": path.is_file(),
            "path": str(path),
            "size": path.stat().st_size if path.is_file() else 0,
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        path = self._path(context)
        if not path.is_file():
            raise FileNotFoundError(path)
        content = read_bounded_path(path)
        digest = hashlib.sha256(content).hexdigest()
        if (
            bool(context.configuration.get("skip_unchanged", True))
            and cursor.get("file_sha256") == digest
        ):
            return PullBatch(
                records=[],
                next_cursor={"file_sha256": digest, "complete": True},
                complete=True,
                metadata={"path": str(path), "sha256": digest, "unchanged": True},
            )

        file_format = str(
            context.configuration.get("format")
            or ("jsonl" if path.suffix.lower() in {".jsonl", ".ndjson"} else "json")
        ).lower()
        encoding = str(context.configuration.get("encoding", "utf-8-sig")) or "utf-8-sig"
        text = content.decode(encoding)
        if file_format == "jsonl":
            records: list[Mapping[str, Any]] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                maximum_line = configured_limit(
                    "THREATBRIDGE_MAX_JSONL_LINE_BYTES", 1024 * 1024
                )
                if len(line.encode("utf-8")) > maximum_line:
                    raise ValueError(
                        f"JSON Lines record {line_number} exceeds the configured line limit"
                    )
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON Lines record at line {line_number}: {exc.msg}"
                    ) from exc
                if not isinstance(value, Mapping):
                    raise ValueError(f"JSON Lines record {line_number} is not an object")
                validate_json_value(value)
                records.append(dict(value))
        else:
            payload = json.loads(text)
            validate_json_value(payload)
            records = self._resolve_records(
                payload,
                str(context.configuration.get("records_key", "")).strip(),
            )

        maximum = int(
            context.configuration.get(
                "max_records",
                getattr(settings, "THREATBRIDGE_MAX_IMPORT_RECORDS", 100_000),
            )
        )
        if len(records) > maximum:
            raise ValueError(f"JSON contains more than the {maximum:,}-record limit")
        return PullBatch(
            records=records,
            next_cursor={"file_sha256": digest, "complete": True},
            complete=True,
            metadata={
                "path": str(path),
                "sha256": digest,
                "format": file_format,
                "encoding": encoding,
            },
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        envelope = bool(context.configuration.get("envelope")) or {
            "external_id",
            "object_type",
            "normalized",
        }.issubset(raw_record.keys())
        if envelope:
            external_id = str(raw_record.get("external_id", "")).strip()
            object_type = str(raw_record.get("object_type", "")).strip()
            normalized = raw_record.get("normalized")
            if not external_id or not object_type or not isinstance(normalized, Mapping):
                raise ValueError(
                    "ThreatBridge envelope records require external_id, object_type, and normalized"
                )
            source_updated_at = self._parse_datetime(
                raw_record.get("source_updated_at") or raw_record.get("updated_at")
            )
            return SourceRecord(
                external_id=external_id,
                object_type=object_type,
                natural_key=str(raw_record.get("natural_key", "")),
                source_updated_at=source_updated_at,
                raw=dict(raw_record),
                normalized=dict(normalized),
            )

        object_type = str(context.configuration.get("object_type", "")).strip()
        if not object_type:
            raise ValueError("JSON adapter requires object_type unless envelope mode is enabled")
        id_fields = context.configuration.get("id_fields") or context.configuration.get("id_field")
        if isinstance(id_fields, str):
            id_fields = [item.strip() for item in id_fields.split(",") if item.strip()]
        if not isinstance(id_fields, list) or not id_fields:
            raise ValueError("JSON adapter requires id_fields or id_field")

        id_values: list[str] = []
        missing: list[str] = []
        for field in id_fields:
            value = self._lookup(raw_record, str(field), default="")
            text = str(value or "").strip()
            if not text:
                missing.append(str(field))
            id_values.append(text)
        if missing:
            raise ValueError(f"JSON record is missing ID fields: {', '.join(missing)}")

        field_map = context.configuration.get("field_map", {})
        if field_map and not isinstance(field_map, dict):
            raise ValueError("field_map must be an object")
        passthrough = bool(context.configuration.get("passthrough_unmapped", True))
        normalized: dict[str, Any] = dict(raw_record) if passthrough else {}
        for source, destination in field_map.items():
            normalized[str(destination)] = self._lookup(raw_record, str(source))

        natural_key_field = str(context.configuration.get("natural_key_field", "")).strip()
        updated_at_field = str(context.configuration.get("updated_at_field", "")).strip()
        return SourceRecord(
            external_id="|".join(id_values),
            object_type=object_type,
            natural_key=(
                str(self._lookup(raw_record, natural_key_field, default=""))
                if natural_key_field
                else ""
            ),
            source_updated_at=(
                self._parse_datetime(self._lookup(raw_record, updated_at_field))
                if updated_at_field
                else None
            ),
            raw=dict(raw_record),
            normalized=normalized,
        )

    @staticmethod
    def _parse_datetime(value: Any) -> datetime | None:
        if value in (None, ""):
            return None
        return parse_source_datetime(value)
