from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from django.conf import settings

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime


class MitreAttackStixAdapter(IntegrationAdapter):
    adapter_key = "mitre-attack-stix"
    supported_object_types = ("attack_technique",)
    configuration_schema = {
        "required": ["path"],
        "properties": {
            "path": {"type": "string"},
            "page_size": {"type": "integer", "minimum": 1},
            "attack_version": {"type": "string"},
        },
    }
    display_name = "MITRE ATT&CK STIX 2.1"
    description = "Imports ATT&CK techniques from an official local STIX bundle."
    configuration_example = {
        "path": "incoming/enterprise-attack.json",
        "page_size": 500,
        "attack_version": "19.1",
    }

    def _resolve_path(self, context: SyncContext) -> Path:
        configured = str(context.configuration.get("path", "")).strip()
        if not configured:
            raise ValueError("MITRE ATT&CK adapter requires configuration.path")
        base = Path(settings.THREATBRIDGE_DATA_DIR).resolve()
        candidate = (base / configured).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValueError("STIX path must remain inside THREATBRIDGE_DATA_DIR")
        return candidate

    def _techniques(self, context: SyncContext) -> list[Mapping[str, Any]]:
        path = self._resolve_path(context)
        if not path.is_file():
            raise FileNotFoundError(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        objects = payload.get("objects", []) if isinstance(payload, Mapping) else []
        if not isinstance(objects, list):
            raise ValueError("STIX bundle must contain an objects array")
        return [item for item in objects if item.get("type") == "attack-pattern"]

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        path = self._resolve_path(context)
        techniques = self._techniques(context)
        return {
            "ok": True,
            "path": str(path),
            "technique_count": len(techniques),
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        techniques = self._techniques(context)
        page_size = max(1, int(context.configuration.get("page_size", 500)))
        offset = max(0, int(cursor.get("offset", 0)))
        page = techniques[offset : offset + page_size]
        next_offset = offset + len(page)
        has_more = next_offset < len(techniques)
        return PullBatch(
            records=page,
            next_cursor={"offset": next_offset} if has_more else {},
            has_more=has_more,
            snapshot_complete=not has_more,
            source_metadata={"total_techniques": len(techniques)},
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        attack_id = ""
        for reference in raw_record.get("external_references", []):
            candidate = str(reference.get("external_id", "")).strip()
            if candidate.startswith("T"):
                attack_id = candidate
                break
        if not attack_id:
            raise ValueError("ATT&CK attack-pattern is missing an external technique ID")
        tactics = [
            str(item.get("phase_name", "")).strip()
            for item in raw_record.get("kill_chain_phases", [])
            if item.get("phase_name")
        ]
        source_updated_at = parse_source_datetime(raw_record.get("modified"))
        return SourceRecord(
            external_id=str(raw_record["id"]),
            object_type="attack_technique",
            natural_key=attack_id,
            source_updated_at=source_updated_at,
            raw=dict(raw_record),
            normalized={
                "attack_id": attack_id,
                "stix_id": raw_record.get("id", ""),
                "name": raw_record.get("name", attack_id),
                "description": raw_record.get("description", ""),
                "tactics": tactics,
                "platforms": raw_record.get("x_mitre_platforms", []),
                "data_sources": raw_record.get("x_mitre_data_sources", []),
                "attack_version": context.configuration.get("attack_version", ""),
                "revoked": bool(raw_record.get("revoked", False)),
                "deprecated": bool(raw_record.get("x_mitre_deprecated", False)),
                "metadata": {
                    "created": raw_record.get("created"),
                    "modified": raw_record.get("modified"),
                    "spec_version": raw_record.get("spec_version"),
                },
            },
        )
