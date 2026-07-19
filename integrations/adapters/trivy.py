from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from django.conf import settings

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime


class TrivyJsonAdapter(IntegrationAdapter):
    adapter_key = "trivy-json"
    supported_object_types = ("vulnerability_finding",)
    configuration_schema = {
        "required": ["path"],
        "properties": {"path": {"type": "string"}},
    }
    display_name = "Trivy JSON report"
    description = "Imports container, filesystem, or repository vulnerability results from JSON."
    configuration_example = {"path": "incoming/trivy.json"}

    def _resolve_path(self, context: SyncContext) -> Path:
        configured = str(context.configuration.get("path", "")).strip()
        if not configured:
            raise ValueError("Trivy adapter requires configuration.path")
        base = Path(settings.THREATBRIDGE_DATA_DIR).resolve()
        candidate = (base / configured).resolve()
        if candidate != base and base not in candidate.parents:
            raise ValueError("Trivy path must remain inside THREATBRIDGE_DATA_DIR")
        return candidate

    def _records(self, context: SyncContext) -> list[Mapping[str, Any]]:
        path = self._resolve_path(context)
        payload = json.loads(path.read_text(encoding="utf-8"))
        records: list[Mapping[str, Any]] = []
        target = (
            payload.get("ArtifactName")
            or payload.get("Metadata", {}).get("ImageID")
            or "unknown"
        )
        digest = payload.get("Metadata", {}).get("RepoDigests", [])
        for result in payload.get("Results", []) or []:
            for vulnerability in result.get("Vulnerabilities", []) or []:
                records.append(
                    {
                        "artifact_name": target,
                        "repo_digests": digest,
                        "target": result.get("Target", target),
                        "class": result.get("Class", ""),
                        "type": result.get("Type", ""),
                        "vulnerability": vulnerability,
                    }
                )
        return records

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        path = self._resolve_path(context)
        return {"ok": path.is_file(), "path": str(path), "findings": len(self._records(context))}

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        path = self._resolve_path(context)
        records = self._records(context)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return PullBatch(
            records=records,
            next_cursor={"file_sha256": digest},
            snapshot_complete=True,
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        vulnerability = raw_record.get("vulnerability", {})
        cve_id = str(vulnerability.get("VulnerabilityID", "")).strip().upper()
        package = str(vulnerability.get("PkgName", "")).strip()
        installed = str(vulnerability.get("InstalledVersion", "")).strip()
        artifact = str(raw_record.get("artifact_name", "")).strip()
        target = str(raw_record.get("target", artifact)).strip()
        if not cve_id or not artifact:
            raise ValueError("Trivy vulnerability requires VulnerabilityID and artifact name")
        cvss_scores = []
        for source in (vulnerability.get("CVSS") or {}).values():
            if isinstance(source, Mapping):
                for key in ("V3Score", "V2Score"):
                    if source.get(key) is not None:
                        cvss_scores.append(source[key])
        external_id = "|".join((artifact, target, package, installed, cve_id))
        recommendation = ""
        fixed_version = str(vulnerability.get("FixedVersion", "")).strip()
        if fixed_version:
            recommendation = f"Upgrade {package} to {fixed_version} or later."
        return SourceRecord(
            external_id=external_id,
            object_type="vulnerability_finding",
            natural_key=cve_id,
            source_updated_at=parse_source_datetime(vulnerability.get("LastModifiedDate")),
            raw=dict(raw_record),
            normalized={
                "asset_external_id": artifact,
                "hostname": artifact,
                "cve_id": cve_id,
                "title": vulnerability.get("Title", ""),
                "description": vulnerability.get("Description", ""),
                "severity": vulnerability.get("Severity", "unknown"),
                "cvss_score": max(cvss_scores) if cvss_scores else None,
                "vendor": raw_record.get("type", ""),
                "product": package,
                "version": installed,
                "status": "open",
                "recommendation": recommendation,
                "published_at": vulnerability.get("PublishedDate"),
                "modified_at": vulnerability.get("LastModifiedDate"),
                "metadata": {
                    "fixed_version": fixed_version,
                    "primary_url": vulnerability.get("PrimaryURL"),
                    "references": vulnerability.get("References", []),
                    "target": target,
                    "class": raw_record.get("class"),
                    "repo_digests": raw_record.get("repo_digests", []),
                },
            },
        )
