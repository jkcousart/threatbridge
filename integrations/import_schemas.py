from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from .models import Integration

OBJECT_TYPE_SCHEMAS: dict[str, dict[str, Any]] = {
    "asset": {
        "label": "Asset",
        "kind": Integration.Kind.ASSET,
        "id_candidates": [
            "asset_external_id",
            "device_id",
            "asset_id",
            "device.identity.id",
            "device.id",
            "id",
            "hostname",
            "fqdn",
        ],
        "fields": {
            "asset_external_id": [
                "asset_external_id",
                "device_id",
                "asset_id",
                "machine_id",
                "device.identity.id",
                "device.id",
                "id",
            ],
            "hostname": [
                "hostname",
                "device_name",
                "computer_name",
                "device.name",
                "host",
                "name",
            ],
            "fqdn": ["fqdn", "fully_qualified_domain_name", "dns_name"],
            "entra_device_id": ["entra_device_id", "aad_device_id", "azure_ad_device_id"],
            "os_platform": [
                "os_platform",
                "device.platform",
                "platform",
                "operating_system",
                "os",
            ],
            "os_version": ["os_version", "operating_system_version"],
            "environment": ["environment", "env"],
            "business_service": ["business_service", "application", "service"],
            "owner": ["owner", "technical_owner", "business_owner"],
            "criticality": ["criticality", "business_criticality", "asset_criticality"],
            "internet_exposed": ["internet_exposed", "externally_exposed", "public_facing"],
            "last_seen_at": ["last_seen_at", "last_seen", "last_seen_timestamp"],
        },
    },
    "software_installation": {
        "label": "Software installation",
        "kind": Integration.Kind.ASSET,
        "id_candidates": ["installation_id", "id"],
        "composite_id_candidates": [
            ["asset_external_id", "product", "version"],
            ["device_id", "software_name", "software_version"],
            ["hostname", "product", "version"],
        ],
        "fields": {
            "asset_external_id": ["asset_external_id", "device_id", "asset_id", "machine_id"],
            "hostname": ["hostname", "device_name", "computer_name", "host"],
            "vendor": ["vendor", "software_vendor", "publisher", "manufacturer"],
            "product": ["product", "software_name", "application_name", "name"],
            "version": ["version", "software_version", "installed_version"],
            "first_seen_at": ["first_seen_at", "first_seen", "installed_at"],
            "last_seen_at": ["last_seen_at", "last_seen"],
            "end_of_support_status": ["end_of_support_status", "eos_status"],
            "end_of_support_date": ["end_of_support_date", "eos_date"],
        },
    },
    "vulnerability": {
        "label": "Vulnerability",
        "kind": Integration.Kind.VULNERABILITY,
        "id_candidates": ["cve_id", "cve", "vulnerability_id", "id"],
        "fields": {
            "cve_id": ["cve_id", "cve", "vulnerability_id", "name", "id"],
            "title": ["title", "vulnerability_title", "name"],
            "description": ["description", "summary"],
            "severity": ["severity", "risk", "priority"],
            "cvss_score": ["cvss_score", "cvss", "base_score"],
            "exploitability": ["exploitability", "exploitability_level", "exploit_status"],
            "known_exploited": ["known_exploited", "kev", "is_known_exploited"],
            "exploit_available": ["exploit_available", "public_exploit", "has_exploit"],
            "published_at": ["published_at", "published", "published_date"],
            "modified_at": ["modified_at", "modified", "updated_at", "last_modified"],
        },
    },
    "vulnerability_finding": {
        "label": "Vulnerability finding",
        "kind": Integration.Kind.VULNERABILITY,
        "id_candidates": ["finding_id", "id"],
        "composite_id_candidates": [
            ["asset_external_id", "cve_id", "product", "version"],
            ["device_id", "cve", "software_name", "software_version"],
            ["hostname", "cve_id"],
        ],
        "fields": {
            "asset_external_id": ["asset_external_id", "device_id", "asset_id", "machine_id"],
            "hostname": ["hostname", "device_name", "computer_name", "host"],
            "criticality": ["criticality", "asset_criticality"],
            "internet_exposed": ["internet_exposed", "externally_exposed", "public_facing"],
            "cve_id": ["cve_id", "cve", "vulnerability_id"],
            "title": ["title", "vulnerability_title", "name"],
            "description": ["description", "summary"],
            "severity": ["severity", "risk", "priority"],
            "cvss_score": ["cvss_score", "cvss", "base_score"],
            "exploitability": ["exploitability", "exploitability_level", "exploit_status"],
            "known_exploited": ["known_exploited", "kev", "is_known_exploited"],
            "exploit_available": ["exploit_available", "public_exploit", "has_exploit"],
            "vendor": ["vendor", "software_vendor", "publisher", "manufacturer"],
            "product": ["product", "software_name", "application_name", "package_name"],
            "version": ["version", "software_version", "installed_version"],
            "status": ["status", "finding_status", "state"],
            "first_seen_at": ["first_seen_at", "first_seen"],
            "last_seen_at": ["last_seen_at", "last_seen"],
            "recommendation": ["recommendation", "remediation", "solution"],
        },
    },
    "attack_technique": {
        "label": "MITRE ATT&CK technique",
        "kind": Integration.Kind.THREAT_INTELLIGENCE,
        "id_candidates": ["attack_id", "technique_id", "external_id", "id"],
        "fields": {
            "attack_id": ["attack_id", "technique_id", "mitre_id", "external_id", "id"],
            "name": ["name", "technique_name", "title"],
            "description": ["description", "summary"],
            "tactics": ["tactics", "tactic"],
            "platforms": ["platforms", "platform"],
            "data_sources": ["data_sources", "telemetry_sources", "telemetry"],
            "revoked": ["revoked"],
            "deprecated": ["deprecated"],
            "attack_version": ["attack_version", "version"],
        },
    },
    "telemetry_source": {
        "label": "Telemetry source",
        "kind": Integration.Kind.DETECTION,
        "id_candidates": ["key", "telemetry_id", "id", "name"],
        "fields": {
            "key": ["key", "telemetry_id", "data_source_id", "id"],
            "name": ["name", "telemetry_name", "data_source"],
            "description": ["description", "summary"],
            "available": ["available", "enabled", "ingesting"],
        },
    },
    "detection_rule": {
        "label": "Detection rule",
        "kind": Integration.Kind.DETECTION,
        "id_candidates": ["detection_id", "rule_id", "external_id", "id"],
        "fields": {
            "external_id": ["external_id", "detection_id", "rule_id", "policy_id", "id"],
            "name": ["name", "rule_name", "policy_name", "title"],
            "description": ["description", "summary"],
            "query": ["query", "logic", "search", "rule_query"],
            "enabled": ["enabled", "active"],
            "severity": ["severity", "priority"],
            "owner": ["owner", "rule_owner"],
            "updated_at": ["updated_at", "modified_at", "last_modified"],
            "techniques": ["techniques", "attack_techniques", "mitre_techniques", "attack_ids"],
            "telemetry_sources": ["telemetry_sources", "telemetry", "data_sources"],
        },
    },
    "validation_test": {
        "label": "Validation test",
        "kind": Integration.Kind.VALIDATION,
        "id_candidates": ["test_id", "external_id", "id"],
        "fields": {
            "test_id": ["test_id", "external_id", "id"],
            "name": ["name", "test_name", "title"],
            "description": ["description", "summary"],
            "procedure": ["procedure", "steps", "command"],
            "enabled": ["enabled", "active"],
            "techniques": ["techniques", "attack_techniques", "attack_ids"],
        },
    },
    "validation_result": {
        "label": "Validation result",
        "kind": Integration.Kind.VALIDATION,
        "id_candidates": ["result_id", "execution_id", "id"],
        "composite_id_candidates": [
            ["test_id", "executed_at", "technique_id"],
            ["test_id", "execution_date", "attack_technique"],
        ],
        "fields": {
            "test_id": ["test_id", "validation_test_id"],
            "test_name": ["test_name", "name", "title"],
            "technique_id": ["technique_id", "attack_technique", "attack_id"],
            "detection_id": ["detection_id", "rule_id", "detection_external_id"],
            "outcome": ["outcome", "status", "result"],
            "executed_at": ["executed_at", "execution_date", "timestamp"],
            "summary": ["summary", "notes", "detail"],
            "evidence": ["evidence", "evidence_url", "artifact"],
        },
    },
    "threat_report": {
        "label": "Threat report",
        "kind": Integration.Kind.THREAT_INTELLIGENCE,
        "id_candidates": ["report_id", "external_id", "id", "name", "title"],
        "fields": {
            "report_id": ["report_id", "external_id", "id"],
            "title": ["title", "name"],
            "summary": ["summary", "description", "content"],
            "source_name": ["source_name", "publisher", "source"],
            "source_url": ["source_url", "url", "reference"],
            "published_at": ["published_at", "published", "created_at"],
            "confidence": ["confidence", "confidence_score"],
            "tlp": ["tlp", "marking", "traffic_light_protocol"],
            "targeted_industries": ["targeted_industries", "industries", "sectors"],
            "techniques": ["techniques", "attack_techniques", "attack_ids"],
            "vulnerabilities": ["vulnerabilities", "cves", "cve_ids"],
            "observables": ["observables", "indicators", "iocs"],
        },
    },
}


IMPORT_OBJECT_TYPE_CHOICES = [
    ("auto", "Auto-detect from fields"),
    ("mixed", "ThreatBridge JSON envelope (mixed object types)"),
    *[(key, value["label"]) for key, value in OBJECT_TYPE_SCHEMAS.items()],
]


FIELD_NAME_PATTERN = re.compile(r"[^a-z0-9]+")


def canonical_field_name(value: str) -> str:
    """Normalize snake_case, camelCase, kebab-case, and dotted field names.

    File exports often expose the same logical field as ``device_id``,
    ``deviceId``, or ``Device-ID``. Suggestions should treat those spellings as
    equivalent without changing the source field retained in the import profile.
    """

    return FIELD_NAME_PATTERN.sub("", str(value).strip().casefold())


def normalized_field_lookup(fields: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    leaf_candidates: dict[str, list[str]] = defaultdict(list)
    for raw_field in fields:
        field = str(raw_field).strip()
        if not field:
            continue
        result.setdefault(field.casefold(), field)
        result.setdefault(canonical_field_name(field), field)
        leaf = field.rsplit(".", 1)[-1]
        leaf_candidates[leaf.casefold()].append(field)
        leaf_candidates[canonical_field_name(leaf)].append(field)

    # Dotted JSON paths can be matched by a unique leaf name. Ambiguous leaves
    # are deliberately omitted so the preview never silently chooses the wrong
    # nested value.
    for key, candidates in leaf_candidates.items():
        unique_candidates = list(dict.fromkeys(candidates))
        if len(unique_candidates) == 1:
            result.setdefault(key, unique_candidates[0])
    return result


def _lookup_field(lookup: Mapping[str, str], alias: str) -> str | None:
    return lookup.get(str(alias).casefold()) or lookup.get(canonical_field_name(alias))


def _has_field(lookup: Mapping[str, str], aliases: Iterable[str]) -> bool:
    return any(_lookup_field(lookup, alias) for alias in aliases)


def suggest_object_type(fields: Iterable[str], sample: Mapping[str, Any] | None = None) -> str:
    lookup = normalized_field_lookup(fields)
    if all(_lookup_field(lookup, field) for field in ("external_id", "object_type", "normalized")):
        return "mixed"
    if sample and isinstance(sample.get("normalized"), Mapping) and sample.get("object_type"):
        return "mixed"

    has_cve = _has_field(
        lookup,
        {"cve_id", "cve", "vulnerability_id", "vulnerabilityId"},
    )
    has_asset = _has_field(
        lookup,
        {
            "asset_external_id",
            "asset_id",
            "device_id",
            "machine_id",
            "device.identity.id",
            "device.id",
            "device.name",
            "hostname",
            "device_name",
        },
    )
    has_software = _has_field(
        lookup,
        {
            "product",
            "software_name",
            "application_name",
            "package_name",
            "pkgName",
        },
    )
    if has_cve and has_asset:
        return "vulnerability_finding"
    if has_cve:
        return "vulnerability"
    if _has_field(lookup, {"attack_id", "technique_id", "mitre_id", "x_mitre_id"}):
        if _has_field(lookup, {"outcome", "result", "execution_id", "executed_at"}):
            return "validation_result"
        if _has_field(lookup, {"rule_id", "detection_id", "query", "logic"}):
            return "detection_rule"
        return "attack_technique"
    if _has_field(lookup, {"rule_id", "detection_id", "policy_id", "rule_name", "query"}):
        return "detection_rule"
    if _has_field(lookup, {"result_id", "execution_id", "outcome"}) and _has_field(
        lookup,
        {"test_id", "test_name"},
    ):
        return "validation_result"
    if _has_field(lookup, {"test_id", "test_name", "procedure"}):
        return "validation_test"
    if _has_field(lookup, {"report_id", "targeted_industries", "observables", "iocs"}):
        return "threat_report"
    if has_software and has_asset:
        return "software_installation"
    if _has_field(lookup, {"telemetry_id", "data_source_id", "ingesting"}):
        return "telemetry_source"
    if has_asset:
        return "asset"
    if _has_field(lookup, {"title", "summary", "description"}) and _has_field(
        lookup,
        {"techniques", "cves"},
    ):
        return "threat_report"
    return "asset"


def suggest_field_map(fields: Iterable[str], object_type: str) -> dict[str, str]:
    schema = OBJECT_TYPE_SCHEMAS.get(object_type, {})
    lookup = normalized_field_lookup(fields)
    result: dict[str, str] = {}
    for destination, aliases in schema.get("fields", {}).items():
        for alias in aliases:
            actual = _lookup_field(lookup, alias)
            if actual:
                result[actual] = destination
                break
    return result


def suggest_id_fields(fields: Iterable[str], object_type: str) -> list[str]:
    if object_type == "mixed":
        return ["external_id"]
    schema = OBJECT_TYPE_SCHEMAS.get(object_type, {})
    lookup = normalized_field_lookup(fields)
    for candidate in schema.get("id_candidates", []):
        actual = _lookup_field(lookup, str(candidate))
        if actual:
            return [actual]
    for group in schema.get("composite_id_candidates", []):
        actual_group = [_lookup_field(lookup, str(candidate)) for candidate in group]
        if all(actual_group):
            return [str(value) for value in actual_group]
    return []


def integration_kind_for_object_type(object_type: str) -> str:
    if object_type == "mixed":
        return Integration.Kind.GENERIC
    return str(OBJECT_TYPE_SCHEMAS.get(object_type, {}).get("kind", Integration.Kind.GENERIC))
