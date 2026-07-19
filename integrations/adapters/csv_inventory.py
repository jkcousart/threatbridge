from __future__ import annotations

import csv
import hashlib
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from django.conf import settings

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime


class CsvInventoryAdapter(IntegrationAdapter):
    """Generic local CSV adapter for exports from enterprise tools."""

    adapter_key = "csv-inventory"
    display_name = "Generic CSV import"
    description = "Maps a local CSV export into a supported normalized object type."
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
        "required": ["path", "object_type", "id_fields"],
        "properties": {
            "path": {"type": "string"},
            "object_type": {"type": "string"},
            "id_fields": {"type": "array"},
            "field_map": {"type": "object"},
            "delimiter": {"type": "string"},
            "encoding": {"type": "string"},
            "passthrough_unmapped": {"type": "boolean"},
            "skip_unchanged": {"type": "boolean"},
        },
    }
    configuration_example = {
        "path": "incoming/software.csv",
        "object_type": "software_installation",
        "id_fields": ["device_id", "software_name", "software_version"],
        "natural_key_field": "software_name",
        "updated_at_field": "updated_at",
        "passthrough_unmapped": True,
        "field_map": {
            "device_id": "asset_external_id",
            "device_name": "hostname",
            "software_vendor": "vendor",
            "software_name": "product",
            "software_version": "version",
        },
    }

    def _resolve_path(self, context: SyncContext) -> Path:
        configured = str(context.configuration.get("path", "")).strip()
        if not configured:
            raise ValueError("CSV adapter requires configuration.path")
        base = Path(settings.THREATBRIDGE_DATA_DIR).resolve()
        candidate = (base / configured).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValueError("CSV path must remain inside THREATBRIDGE_DATA_DIR")
        return candidate

    @staticmethod
    def _delimiter(context: SyncContext) -> str:
        delimiter = str(context.configuration.get("delimiter", ","))
        if delimiter == "\\t":
            delimiter = "\t"
        if len(delimiter) != 1:
            raise ValueError("CSV delimiter must be one character")
        return delimiter

    @staticmethod
    def _encoding(context: SyncContext) -> str:
        return str(context.configuration.get("encoding", "utf-8-sig")).strip() or "utf-8-sig"

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        path = self._resolve_path(context)
        result: dict[str, Any] = {
            "ok": path.is_file(),
            "path": str(path),
            "size": path.stat().st_size if path.is_file() else 0,
        }
        if path.is_file():
            with path.open(
                "r",
                encoding=self._encoding(context),
                newline="",
            ) as handle:
                reader = csv.reader(handle, delimiter=self._delimiter(context))
                result["fields"] = next(reader, [])
        return result

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        path = self._resolve_path(context)
        if not path.is_file():
            raise FileNotFoundError(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if bool(context.configuration.get("skip_unchanged", True)) and cursor.get(
            "file_sha256"
        ) == digest:
            return PullBatch(
                records=[],
                next_cursor={"file_sha256": digest, "complete": True},
                complete=True,
                metadata={"path": str(path), "sha256": digest, "unchanged": True},
            )

        maximum = int(
            context.configuration.get(
                "max_records",
                getattr(settings, "THREATBRIDGE_MAX_IMPORT_RECORDS", 100_000),
            )
        )
        records: list[Mapping[str, Any]] = []
        with path.open(
            "r",
            encoding=self._encoding(context),
            newline="",
        ) as handle:
            reader = csv.DictReader(handle, delimiter=self._delimiter(context))
            if not reader.fieldnames:
                raise ValueError("CSV file does not contain a header row")
            for row in reader:
                if row is None or not any(value not in (None, "") for value in row.values()):
                    continue
                records.append(dict(row))
                if len(records) > maximum:
                    raise ValueError(f"CSV contains more than the {maximum:,}-record limit")
        return PullBatch(
            records=records,
            next_cursor={"file_sha256": digest, "complete": True},
            complete=True,
            metadata={
                "path": str(path),
                "sha256": digest,
                "delimiter": self._delimiter(context),
                "encoding": self._encoding(context),
            },
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        object_type = str(context.configuration.get("object_type", "")).strip()
        if not object_type:
            raise ValueError("CSV adapter requires configuration.object_type")

        id_fields = context.configuration.get("id_fields") or context.configuration.get(
            "id_field"
        )
        if isinstance(id_fields, str):
            id_fields = [item.strip() for item in id_fields.split(",") if item.strip()]
        if not isinstance(id_fields, list) or not id_fields:
            raise ValueError("CSV adapter requires a non-empty configuration.id_fields list")
        missing = [field for field in id_fields if not str(raw_record.get(field, "")).strip()]
        if missing:
            raise ValueError(f"Missing ID fields: {', '.join(missing)}")

        external_id = "|".join(str(raw_record[field]).strip() for field in id_fields)
        natural_key_field = str(context.configuration.get("natural_key_field", "")).strip()
        updated_at_field = str(context.configuration.get("updated_at_field", "")).strip()
        field_map = context.configuration.get("field_map", {})
        if not isinstance(field_map, dict):
            raise ValueError("configuration.field_map must be an object")

        passthrough = bool(context.configuration.get("passthrough_unmapped", True))
        normalized: dict[str, Any] = dict(raw_record) if passthrough else {}
        for source, destination in field_map.items():
            normalized[str(destination)] = raw_record.get(str(source))

        source_updated_at: datetime | None = None
        if updated_at_field and raw_record.get(updated_at_field):
            source_updated_at = parse_source_datetime(raw_record[updated_at_field])

        return SourceRecord(
            external_id=external_id,
            object_type=object_type,
            natural_key=(
                str(raw_record.get(natural_key_field, "")) if natural_key_field else ""
            ),
            source_updated_at=source_updated_at,
            raw=dict(raw_record),
            normalized=normalized,
        )
