from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime


class DemoAdapter(IntegrationAdapter):
    adapter_key = "demo-scenario"
    supported_object_types = (
        "asset",
        "software_installation",
        "vulnerability",
        "vulnerability_finding",
        "attack_technique",
        "telemetry_source",
        "detection_rule",
        "validation_result",
        "threat_report",
    )
    display_name = "ThreatBridge demo scenario"
    description = "Loads a complete threat-to-control example without external credentials."
    configuration_example = {}

    RECORDS = [
        {
            "external_id": "attack-pattern--t1190",
            "object_type": "attack_technique",
            "natural_key": "T1190",
            "updated_at": "2026-07-18T18:00:00Z",
            "normalized": {
                "attack_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "platforms": ["Linux", "Windows"],
                "data_sources": ["Web application logs"],
                "attack_version": "19.1",
            },
        },
        {
            "external_id": "attack-pattern--t1059-001",
            "object_type": "attack_technique",
            "natural_key": "T1059.001",
            "updated_at": "2026-07-18T18:00:00Z",
            "normalized": {
                "attack_id": "T1059.001",
                "name": "PowerShell",
                "tactics": ["execution"],
                "platforms": ["Windows"],
                "data_sources": ["PowerShell logs"],
                "attack_version": "19.1",
            },
        },
        {
            "external_id": "attack-pattern--t1003",
            "object_type": "attack_technique",
            "natural_key": "T1003",
            "updated_at": "2026-07-18T18:00:00Z",
            "normalized": {
                "attack_id": "T1003",
                "name": "OS Credential Dumping",
                "tactics": ["credential-access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "data_sources": ["Process access events"],
                "attack_version": "19.1",
            },
        },
        {
            "external_id": "asset-clinical-web-01",
            "object_type": "asset",
            "natural_key": "clinical-web-01",
            "updated_at": "2026-07-18T18:05:00Z",
            "normalized": {
                "asset_external_id": "clinical-web-01",
                "hostname": "clinical-web-01.corp.example",
                "os_platform": "Linux",
                "environment": "production",
                "business_service": "Patient Scheduling",
                "owner": "Clinical Applications",
                "criticality": "critical",
                "internet_exposed": True,
            },
        },
        {
            "external_id": "asset-admin-ws-02",
            "object_type": "asset",
            "natural_key": "admin-ws-02",
            "updated_at": "2026-07-18T18:05:00Z",
            "normalized": {
                "asset_external_id": "admin-ws-02",
                "hostname": "admin-ws-02.corp.example",
                "os_platform": "Windows 11",
                "environment": "production",
                "business_service": "Corporate Administration",
                "owner": "Workplace Technology",
                "criticality": "medium",
                "internet_exposed": False,
            },
        },
        {
            "external_id": "software-clinical-web-01-nginx-1.24.0",
            "object_type": "software_installation",
            "natural_key": "nginx",
            "updated_at": "2026-07-18T18:06:00Z",
            "normalized": {
                "asset_external_id": "clinical-web-01",
                "hostname": "clinical-web-01.corp.example",
                "vendor": "F5",
                "product": "nginx",
                "version": "1.24.0",
                "last_seen_at": "2026-07-18T18:06:00Z",
            },
        },
        {
            "external_id": "vulnerability-cve-2026-0001",
            "object_type": "vulnerability",
            "natural_key": "CVE-2026-0001",
            "updated_at": "2026-07-18T18:10:00Z",
            "normalized": {
                "cve_id": "CVE-2026-0001",
                "title": "Demo public-facing application vulnerability",
                "severity": "critical",
                "cvss_score": 9.8,
                "exploitability": "ExploitIsVerified",
            },
        },
        {
            "external_id": "vulnerability-cve-2026-0002",
            "object_type": "vulnerability",
            "natural_key": "CVE-2026-0002",
            "updated_at": "2026-07-18T18:10:00Z",
            "normalized": {
                "cve_id": "CVE-2026-0002",
                "title": "Demo unobserved vulnerability",
                "severity": "high",
                "cvss_score": 8.1,
            },
        },
        {
            "external_id": "finding-clinical-web-01-cve-2026-0001",
            "object_type": "vulnerability_finding",
            "natural_key": "CVE-2026-0001",
            "updated_at": "2026-07-18T18:11:00Z",
            "normalized": {
                "asset_external_id": "clinical-web-01",
                "hostname": "clinical-web-01.corp.example",
                "criticality": "critical",
                "internet_exposed": True,
                "cve_id": "CVE-2026-0001",
                "severity": "critical",
                "exploitability": "ExploitIsVerified",
                "vendor": "F5",
                "product": "nginx",
                "version": "1.24.0",
                "status": "open",
                "recommendation": "Apply the vendor-provided fixed version.",
                "first_seen_at": "2026-07-17T12:00:00Z",
                "last_seen_at": "2026-07-18T18:11:00Z",
            },
        },
        {
            "external_id": "telemetry-web-application-logs",
            "object_type": "telemetry_source",
            "natural_key": "web_application_logs",
            "updated_at": "2026-07-18T18:15:00Z",
            "normalized": {
                "key": "web_application_logs",
                "name": "Web application logs",
                "available": True,
                "last_verified_at": "2026-07-18T18:15:00Z",
            },
        },
        {
            "external_id": "telemetry-powershell-logs",
            "object_type": "telemetry_source",
            "natural_key": "powershell_logs",
            "updated_at": "2026-07-18T18:15:00Z",
            "normalized": {
                "key": "powershell_logs",
                "name": "PowerShell logs",
                "available": True,
                "last_verified_at": "2026-07-18T18:15:00Z",
            },
        },
        {
            "external_id": "telemetry-process-access-events",
            "object_type": "telemetry_source",
            "natural_key": "process_access_events",
            "updated_at": "2026-07-18T18:15:00Z",
            "normalized": {
                "key": "process_access_events",
                "name": "Process access events",
                "available": False,
                "last_verified_at": "2026-07-18T18:15:00Z",
            },
        },
        {
            "external_id": "detection-det-1190",
            "object_type": "detection_rule",
            "natural_key": "DET-1190",
            "updated_at": "2026-07-18T18:20:00Z",
            "normalized": {
                "external_id": "DET-1190",
                "name": "Suspicious public-facing exploitation sequence",
                "description": "Detects exploitation patterns against exposed web services.",
                "enabled": True,
                "severity": "high",
                "owner": "Detection Engineering",
                "techniques": ["T1190"],
                "telemetry": [
                    {
                        "key": "web_application_logs",
                        "name": "Web application logs",
                        "available": True,
                    }
                ],
            },
        },
        {
            "external_id": "detection-det-1059-001",
            "object_type": "detection_rule",
            "natural_key": "DET-1059-001",
            "updated_at": "2026-07-18T18:20:00Z",
            "normalized": {
                "external_id": "DET-1059-001",
                "name": "Suspicious PowerShell execution",
                "enabled": True,
                "severity": "medium",
                "owner": "Detection Engineering",
                "techniques": ["T1059.001"],
                "telemetry": [
                    {
                        "key": "powershell_logs",
                        "name": "PowerShell logs",
                        "available": True,
                    }
                ],
            },
        },
        {
            "external_id": "detection-det-1003",
            "object_type": "detection_rule",
            "natural_key": "DET-1003",
            "updated_at": "2026-07-18T18:20:00Z",
            "normalized": {
                "external_id": "DET-1003",
                "name": "Credential dumping process access",
                "enabled": True,
                "severity": "high",
                "owner": "Detection Engineering",
                "techniques": ["T1003"],
                "telemetry": [
                    {
                        "key": "process_access_events",
                        "name": "Process access events",
                        "available": False,
                    }
                ],
            },
        },
        {
            "external_id": "validation-val-1190",
            "object_type": "validation_result",
            "natural_key": "VAL-1190",
            "updated_at": "2026-07-18T18:25:00Z",
            "normalized": {
                "external_id": "VAL-1190",
                "detection_external_id": "DET-1190",
                "attack_id": "T1190",
                "status": "passed",
                "executed_at": "2026-07-18T18:25:00Z",
                "evidence": "The expected alert and supporting web events were observed.",
            },
        },
        {
            "external_id": "validation-val-1059-001",
            "object_type": "validation_result",
            "natural_key": "VAL-1059-001",
            "updated_at": "2026-07-18T18:26:00Z",
            "normalized": {
                "external_id": "VAL-1059-001",
                "detection_external_id": "DET-1059-001",
                "attack_id": "T1059.001",
                "status": "partial",
                "executed_at": "2026-07-18T18:26:00Z",
                "evidence": "PowerShell telemetry arrived, but the expected alert was delayed.",
            },
        },
        {
            "external_id": "report-healthcare-demo-campaign",
            "object_type": "threat_report",
            "natural_key": "Healthcare-targeting demo campaign",
            "updated_at": "2026-07-18T18:30:00Z",
            "normalized": {
                "title": "Healthcare-targeting demo exploitation campaign",
                "summary": (
                    "A demonstration report linking public-facing exploitation, PowerShell, "
                    "credential access, and two vulnerabilities."
                ),
                "source_name": "ThreatBridge demonstration",
                "published_at": "2026-07-18T18:30:00Z",
                "confidence": 85,
                "marking": "TLP:CLEAR",
                "techniques": [
                    {
                        "attack_id": "T1190",
                        "confidence": 95,
                        "evidence_excerpt": "The actor exploited an internet-facing service.",
                    },
                    {
                        "attack_id": "T1059.001",
                        "confidence": 90,
                        "evidence_excerpt": "PowerShell was used for execution.",
                    },
                    {
                        "attack_id": "T1003",
                        "confidence": 80,
                        "evidence_excerpt": "Credential material was collected from memory.",
                    },
                ],
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2026-0001",
                        "confidence": 95,
                        "evidence_excerpt": "The campaign exploited CVE-2026-0001.",
                    },
                    {
                        "cve_id": "CVE-2026-0002",
                        "confidence": 60,
                        "evidence_excerpt": "CVE-2026-0002 was reported as an alternate path.",
                    },
                ],
            },
        },
    ]

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        return {
            "ok": True,
            "integration": context.integration_slug,
            "records": len(self.RECORDS),
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        return PullBatch(
            records=self.RECORDS,
            next_cursor={"complete": True, "record_count": len(self.RECORDS)},
            snapshot_complete=True,
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        updated_at: datetime | None = parse_source_datetime(raw_record.get("updated_at"))
        return SourceRecord(
            external_id=str(raw_record["external_id"]),
            object_type=str(raw_record["object_type"]),
            natural_key=str(raw_record.get("natural_key", "")),
            source_updated_at=updated_at,
            raw=dict(raw_record),
            normalized=dict(raw_record["normalized"]),
        )
