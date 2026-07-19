from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.utils.text import slugify

from catalog.models import (
    Asset,
    AssetAlias,
    AssetSource,
    AttackTechnique,
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleTelemetry,
    Observable,
    SoftwareInstallation,
    SoftwareProduct,
    TelemetrySource,
    ThreatReport,
    ThreatReportTechnique,
    ThreatReportVulnerability,
    ValidationResult,
    ValidationTest,
    Vulnerability,
    VulnerabilityFinding,
)
from integrations.models import ExternalObject, Integration

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _first(mapping: Mapping[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = mapping.get(key)
        if value is not None and value != "":
            return value
    return default


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


def _bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "enabled", "available"}:
        return True
    if text in {"false", "0", "no", "n", "disabled", "unavailable"}:
        return False
    return None


def _datetime(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        result = value
    else:
        result = parse_datetime(str(value).replace("Z", "+00:00"))
    if result and timezone.is_naive(result):
        result = timezone.make_aware(result, timezone=UTC)
    return result


def _date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    return parse_date(str(value)[:10])


def _decimal(value: Any) -> Decimal | None:
    if value in (None, ""):
        return None
    try:
        return Decimal(str(value)).quantize(Decimal("0.1"))
    except (InvalidOperation, ValueError):
        return None


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    return " ".join(_clean(value).lower().split())


def _validation_outcome(value: Any) -> str:
    outcome = _clean(value).lower().replace(" ", "_")
    if outcome in {"pass", "success"}:
        return "passed"
    if outcome == "fail":
        return "failed"
    if outcome == "incomplete":
        return "partial"
    return outcome


def _cve(value: Any) -> str:
    candidate = _clean(value).upper()
    return candidate if CVE_PATTERN.fullmatch(candidate) else ""


def _technique_id(value: Any) -> str:
    candidate = _clean(value).upper()
    return candidate if TECHNIQUE_PATTERN.fullmatch(candidate) else ""


def _update_nonempty(instance: Any, values: Mapping[str, Any]) -> bool:
    changed = False
    for field, value in values.items():
        if value is None or value == "":
            continue
        if getattr(instance, field) != value:
            setattr(instance, field, value)
            changed = True
    return changed


def _asset_payload(normalized: Mapping[str, Any]) -> dict[str, Any]:
    nested = _mapping(normalized.get("asset"))
    return {
        "external_id": _first(
            normalized,
            "asset_external_id",
            "device_id",
            "asset_id",
            default=_first(nested, "external_id", "device_id", "id"),
        ),
        "hostname": _first(
            normalized,
            "hostname",
            "device_name",
            default=_first(nested, "hostname", "device_name", "name"),
        ),
        "fqdn": _first(normalized, "fqdn", default=_first(nested, "fqdn")),
        "entra_device_id": _first(
            normalized,
            "entra_device_id",
            "aad_device_id",
            default=_first(nested, "entra_device_id", "aad_device_id"),
        ),
        "os_platform": _first(
            normalized,
            "os_platform",
            "platform",
            default=_first(nested, "os_platform", "platform"),
        ),
        "os_version": _first(normalized, "os_version", default=_first(nested, "os_version")),
        "environment": _first(normalized, "environment", default=_first(nested, "environment")),
        "business_service": _first(
            normalized,
            "business_service",
            default=_first(nested, "business_service"),
        ),
        "owner": _first(normalized, "owner", default=_first(nested, "owner")),
        "criticality": _first(
            normalized,
            "criticality",
            default=_first(nested, "criticality", default=None),
        ),
        "internet_exposed": _first(
            normalized,
            "internet_exposed",
            default=_first(nested, "internet_exposed", default=None),
        ),
        "last_seen_at": _first(
            normalized,
            "asset_last_seen_at",
            "last_seen_at",
            default=_first(nested, "last_seen_at", default=None),
        ),
        "aliases": _list(
            _first(
                normalized,
                "asset_aliases",
                default=_first(nested, "aliases", default=[]),
            )
        ),
    }


def resolve_asset(
    integration: Integration,
    normalized: Mapping[str, Any],
    source_object: ExternalObject,
) -> Asset:
    payload = _asset_payload(normalized)
    external_id = _clean(payload["external_id"])
    hostname = _clean(payload["hostname"])
    fqdn = _clean(payload["fqdn"]) or (hostname if "." in hostname else "")
    entra_id = _clean(payload["entra_device_id"])

    candidates: list[tuple[str, str, str, str]] = []
    if external_id:
        candidates.append((integration.slug, "external_id", external_id, external_id.lower()))
    if entra_id:
        candidates.append(("global", "entra_device_id", entra_id, entra_id.lower()))
    if fqdn:
        candidates.append(("global", "fqdn", fqdn, fqdn.lower().rstrip(".")))
    if hostname:
        candidates.append((integration.slug, "hostname", hostname, hostname.lower()))

    asset: Asset | None = None
    for namespace, kind, _value, normalized_value in candidates:
        alias = (
            AssetAlias.objects.select_related("asset")
            .filter(namespace=namespace, kind=kind, normalized_value=normalized_value)
            .first()
        )
        if alias:
            asset = alias.asset
            break

    stable_id = external_id or fqdn or hostname or source_object.external_id
    if asset is None:
        asset, _ = Asset.objects.get_or_create(
            canonical_key=f"{integration.slug}:{stable_id.lower()}"[:600],
            defaults={"display_name": (hostname or fqdn or external_id or stable_id)[:255]},
        )

    criticality_value = _clean(payload["criticality"]).lower()
    criticality = (
        criticality_value
        if criticality_value in {"unknown", "low", "medium", "high", "critical"}
        else None
    )
    changed = _update_nonempty(
        asset,
        {
            "display_name": (hostname or fqdn or external_id or asset.display_name)[:255],
            "hostname": hostname[:255],
            "fqdn": fqdn[:500],
            "os_platform": _clean(payload["os_platform"])[:150],
            "os_version": _clean(payload["os_version"])[:150],
            "environment": _clean(payload["environment"])[:100],
            "business_service": _clean(payload["business_service"])[:255],
            "owner": _clean(payload["owner"])[:255],
            "criticality": criticality,
            "internet_exposed": _bool(payload["internet_exposed"]),
            "last_seen_at": _datetime(payload["last_seen_at"]),
        },
    )
    if changed:
        asset.save()

    for item in payload["aliases"]:
        if isinstance(item, Mapping):
            namespace = _clean(item.get("namespace") or integration.slug)
            kind = _clean(item.get("kind") or "alias")
            value = _clean(item.get("value"))
        else:
            namespace = integration.slug
            kind = "alias"
            value = _clean(item)
        if value:
            candidates.append((namespace, kind, value, value.lower()))

    for namespace, kind, value, normalized_value in candidates:
        AssetAlias.objects.update_or_create(
            namespace=namespace[:150],
            kind=kind[:64],
            normalized_value=normalized_value[:600],
            defaults={"asset": asset, "value": value[:600]},
        )

    AssetSource.objects.update_or_create(source_object=source_object, defaults={"asset": asset})
    return asset


def resolve_product(normalized: Mapping[str, Any]) -> SoftwareProduct | None:
    nested = _mapping(normalized.get("software"))
    vendor = _clean(
        _first(
            normalized,
            "vendor",
            "software_vendor",
            default=_first(nested, "vendor", "software_vendor"),
        )
    )
    name = _clean(
        _first(
            normalized,
            "product",
            "software_name",
            "product_name",
            default=_first(nested, "name", "product", "software_name"),
        )
    )
    if not name:
        return None
    product, created = SoftwareProduct.objects.get_or_create(
        normalized_vendor=_norm(vendor),
        normalized_name=_norm(name),
        defaults={
            "vendor": vendor,
            "name": name,
            "cpe": _clean(_first(normalized, "cpe", default=_first(nested, "cpe"))),
        },
    )
    if not created and _update_nonempty(
        product,
        {
            "vendor": vendor,
            "name": name,
            "cpe": _clean(_first(normalized, "cpe", default=_first(nested, "cpe"))),
        },
    ):
        product.save()
    return product


def resolve_vulnerability(normalized: Mapping[str, Any]) -> Vulnerability:
    nested = _mapping(normalized.get("vulnerability"))
    cve_id = _cve(
        _first(
            normalized,
            "cve_id",
            "vulnerability_id",
            default=_first(nested, "cve_id", "id"),
        )
    )
    if not cve_id:
        raise ValueError("Vulnerability projection requires a valid CVE identifier")

    severity = _clean(
        _first(
            normalized,
            "severity",
            "vulnerability_severity",
            default=_first(nested, "severity"),
        )
    ).lower()
    exploitability = _clean(
        _first(
            normalized,
            "exploitability",
            "exploitability_level",
            default=_first(nested, "exploitability"),
        )
    )
    known_exploited = _bool(
        _first(
            normalized,
            "known_exploited",
            default=_first(nested, "known_exploited", default=None),
        )
    )
    exploit_available = _bool(
        _first(
            normalized,
            "exploit_available",
            default=_first(nested, "exploit_available", default=None),
        )
    )
    if exploit_available is None and exploitability:
        exploit_available = exploitability.lower() not in {
            "noexploit",
            "none",
            "unknown",
        }

    vulnerability, _ = Vulnerability.objects.get_or_create(cve_id=cve_id)
    if _update_nonempty(
        vulnerability,
        {
            "title": _clean(
                _first(
                    normalized,
                    "vulnerability_title",
                    "title",
                    default=_first(nested, "title"),
                )
            )[:500],
            "description": _clean(
                _first(
                    normalized,
                    "vulnerability_description",
                    "description",
                    default=_first(nested, "description"),
                )
            ),
            "severity": severity[:32],
            "cvss_score": _decimal(
                _first(
                    normalized,
                    "cvss_score",
                    "cvss",
                    default=_first(nested, "cvss_score", "cvss"),
                )
            ),
            "exploitability": exploitability[:100],
            "known_exploited": known_exploited,
            "exploit_available": exploit_available,
            "published_at": _datetime(
                _first(normalized, "published_at", default=_first(nested, "published_at"))
            ),
            "modified_at": _datetime(
                _first(normalized, "modified_at", default=_first(nested, "modified_at"))
            ),
        },
    ):
        vulnerability.save()
    return vulnerability


def resolve_technique(identifier: Any, name: str = "") -> AttackTechnique:
    technique_id = _technique_id(identifier)
    if not technique_id:
        raise ValueError(f"Invalid ATT&CK technique identifier: {identifier}")
    technique, _ = AttackTechnique.objects.get_or_create(
        technique_id=technique_id,
        defaults={"name": name or technique_id},
    )
    if name and technique.name in {"", technique.technique_id}:
        technique.name = name
        technique.save(update_fields=["name", "updated_at"])
    return technique


def _telemetry_key(name: str) -> str:
    return slugify(name)[:180] or "telemetry"


def _technique_entries(value: Any) -> Iterable[tuple[str, str, int]]:
    for item in _list(value):
        if isinstance(item, Mapping):
            identifier = _first(item, "technique_id", "attack_id", "id", "external_id")
            name = _clean(item.get("name"))
            try:
                confidence = int(item.get("confidence") or 100)
            except (TypeError, ValueError):
                confidence = 100
        else:
            identifier = item
            name = ""
            confidence = 100
        technique_id = _technique_id(identifier)
        if technique_id:
            yield technique_id, name, max(0, min(confidence, 100))


def project_asset(source_object: ExternalObject) -> Asset:
    return resolve_asset(source_object.integration, source_object.normalized, source_object)


def project_software_installation(source_object: ExternalObject) -> SoftwareInstallation:
    normalized = source_object.normalized
    metadata = _mapping(normalized.get("metadata"))
    asset = resolve_asset(source_object.integration, normalized, source_object)
    product = resolve_product(normalized)
    if product is None:
        raise ValueError("Software installation requires product or software_name")
    nested = _mapping(normalized.get("software"))
    version = _clean(
        _first(
            normalized,
            "version",
            "software_version",
            "product_version",
            default=_first(nested, "version", "software_version"),
        )
    )
    installation, _ = SoftwareInstallation.objects.update_or_create(
        source_object=source_object,
        defaults={
            "asset": asset,
            "product": product,
            "version": version[:255],
            "first_seen_at": _datetime(
                _first(normalized, "first_seen_at", "software_first_seen_at")
            ),
            "last_seen_at": _datetime(
                _first(normalized, "last_seen_at", "software_last_seen_at")
            )
            or source_object.source_updated_at,
            "end_of_support_status": _clean(
                _first(
                    normalized,
                    "end_of_support_status",
                    default=_first(metadata, "end_of_support_status"),
                )
            )[:100],
            "end_of_support_date": _date(
                _first(normalized, "end_of_support_date", "end_of_support_at")
            ),
            "evidence": {
                "disk_paths": _list(
                    _first(
                        normalized,
                        "disk_paths",
                        default=_first(metadata, "disk_paths", default=[]),
                    )
                ),
                "registry_paths": _list(
                    _first(
                        normalized,
                        "registry_paths",
                        default=_first(metadata, "registry_paths", default=[]),
                    )
                ),
                "source": source_object.integration.slug,
            },
        },
    )
    return installation


def project_vulnerability(source_object: ExternalObject) -> Vulnerability:
    return resolve_vulnerability(source_object.normalized)


def project_vulnerability_finding(source_object: ExternalObject) -> VulnerabilityFinding:
    normalized = source_object.normalized
    metadata = _mapping(normalized.get("metadata"))
    asset = resolve_asset(source_object.integration, normalized, source_object)
    vulnerability = resolve_vulnerability(normalized)
    product = resolve_product(normalized)
    raw_status = _clean(_first(normalized, "status", "finding_status", default="open"))
    raw_status = raw_status.lower().replace(" ", "_")
    status_aliases = {
        "new": "open",
        "active": "open",
        "remediated": "fixed",
        "closed": "fixed",
        "falsepositive": "false_positive",
    }
    finding_status = status_aliases.get(raw_status, raw_status)
    if finding_status not in dict(VulnerabilityFinding.Status.choices):
        finding_status = VulnerabilityFinding.Status.UNKNOWN
    finding, _ = VulnerabilityFinding.objects.update_or_create(
        source_object=source_object,
        defaults={
            "asset": asset,
            "vulnerability": vulnerability,
            "product": product,
            "installed_version": _clean(
                _first(normalized, "installed_version", "version", "software_version")
            )[:255],
            "severity": _clean(
                _first(normalized, "severity", "vulnerability_severity")
            ).lower()[:32],
            "status": finding_status,
            "first_seen_at": _datetime(_first(normalized, "first_seen_at")),
            "last_seen_at": _datetime(_first(normalized, "last_seen_at"))
            or source_object.source_updated_at,
            "remediation": _clean(
                _first(
                    normalized,
                    "remediation",
                    "recommendation",
                    "recommended_security_update",
                )
            ),
            "evidence": {
                "exploitability": _first(
                    normalized,
                    "exploitability",
                    "exploitability_level",
                ),
                "security_update_available": _bool(
                    _first(
                        normalized,
                        "security_update_available",
                        default=metadata.get("security_update_available"),
                    )
                ),
                "recommendation_reference": _first(
                    normalized,
                    "recommendation_reference",
                    default=metadata.get("recommendation_reference", ""),
                ),
                "source": source_object.integration.slug,
            },
        },
    )
    return finding


def project_attack_technique(source_object: ExternalObject) -> AttackTechnique:
    normalized = source_object.normalized
    technique_id = _technique_id(
        _first(normalized, "technique_id", "external_id", "attack_id")
    )
    if not technique_id:
        raise ValueError("ATT&CK technique projection requires technique_id")
    technique, _ = AttackTechnique.objects.get_or_create(
        technique_id=technique_id,
        defaults={"name": _clean(normalized.get("name")) or technique_id},
    )
    values = {
        "name": _clean(normalized.get("name")) or technique.name,
        "description": _clean(normalized.get("description")),
        "tactics": _list(normalized.get("tactics")),
        "platforms": _list(normalized.get("platforms")),
        "data_sources": _list(normalized.get("data_sources")),
        "revoked": _bool(normalized.get("revoked")) or False,
        "deprecated": _bool(normalized.get("deprecated")) or False,
        "attack_version": _clean(normalized.get("attack_version"))[:64],
        "source_object": source_object,
    }
    if _update_nonempty(technique, values):
        technique.save()
    return technique


def project_telemetry_source(source_object: ExternalObject) -> TelemetrySource:
    normalized = source_object.normalized
    name = _clean(_first(normalized, "name", "telemetry_name", "data_source"))
    if not name:
        raise ValueError("Telemetry source requires a name")
    key = _clean(normalized.get("key")) or _telemetry_key(name)
    telemetry, _ = TelemetrySource.objects.update_or_create(
        key=key[:180],
        defaults={
            "name": name[:255],
            "description": _clean(normalized.get("description")),
            "available": _bool(normalized.get("available")),
            "integration": source_object.integration,
            "source_object": source_object,
            "metadata": dict(_mapping(normalized.get("metadata"))),
        },
    )
    return telemetry


def project_detection_rule(source_object: ExternalObject) -> DetectionRule:
    normalized = source_object.normalized
    external_id = _clean(
        _first(
            normalized,
            "detection_id",
            "rule_id",
            "external_id",
            default=source_object.external_id,
        )
    )
    name = _clean(_first(normalized, "name", "rule_name", "title", default=external_id))
    enabled = _bool(normalized.get("enabled"))
    rule, _ = DetectionRule.objects.update_or_create(
        source_object=source_object,
        defaults={
            "integration": source_object.integration,
            "external_id": external_id[:500],
            "name": name[:500],
            "description": _clean(normalized.get("description")),
            "query": _clean(_first(normalized, "query", "logic")),
            "enabled": True if enabled is None else enabled,
            "severity": _clean(normalized.get("severity")).lower()[:32],
            "owner": _clean(normalized.get("owner"))[:255],
            "source_updated_at": _datetime(normalized.get("updated_at"))
            or source_object.source_updated_at,
            "metadata": dict(_mapping(normalized.get("metadata"))),
        },
    )

    DetectionRuleTechnique.objects.filter(detection_rule=rule).delete()
    for technique_id, technique_name, confidence in _technique_entries(
        _first(normalized, "techniques", "attack_techniques", default=[])
    ):
        DetectionRuleTechnique.objects.create(
            detection_rule=rule,
            technique=resolve_technique(technique_id, technique_name),
            confidence=confidence,
        )

    DetectionRuleTelemetry.objects.filter(detection_rule=rule).delete()
    for item in _list(
        _first(
            normalized,
            "telemetry_sources",
            "telemetry",
            "data_sources",
            default=[],
        )
    ):
        if isinstance(item, Mapping):
            telemetry_name = _clean(_first(item, "name", "data_source", "key"))
            telemetry_key = _clean(item.get("key"))
            available = _bool(item.get("available"))
            required = _bool(item.get("required"))
        else:
            telemetry_name = _clean(item)
            telemetry_key = ""
            available = None
            required = True
        if not telemetry_name:
            continue
        key = telemetry_key[:180] or _telemetry_key(telemetry_name)
        telemetry, _ = TelemetrySource.objects.get_or_create(
            key=key,
            defaults={"name": telemetry_name, "available": available},
        )
        if available is not None and telemetry.available != available:
            telemetry.available = available
            telemetry.save(update_fields=["available", "updated_at"])
        DetectionRuleTelemetry.objects.create(
            detection_rule=rule,
            telemetry_source=telemetry,
            required=True if required is None else required,
        )
    return rule


def project_validation_test(source_object: ExternalObject) -> ValidationTest:
    normalized = source_object.normalized
    external_id = _clean(
        _first(normalized, "test_id", "external_id", default=source_object.external_id)
    )
    name = _clean(_first(normalized, "name", "title", default=external_id))
    enabled = _bool(normalized.get("enabled"))
    test, _ = ValidationTest.objects.update_or_create(
        source_object=source_object,
        defaults={
            "integration": source_object.integration,
            "external_id": external_id[:500],
            "name": name[:500],
            "description": _clean(normalized.get("description")),
            "procedure": _clean(normalized.get("procedure")),
            "enabled": True if enabled is None else enabled,
            "metadata": dict(_mapping(normalized.get("metadata"))),
        },
    )
    test.techniques.clear()
    for technique_id, technique_name, _confidence in _technique_entries(
        normalized.get("techniques")
    ):
        test.techniques.add(resolve_technique(technique_id, technique_name))
    return test


def project_validation_result(source_object: ExternalObject) -> ValidationResult:
    normalized = source_object.normalized
    test_external_id = _clean(
        _first(normalized, "test_id", "validation_test_id", default="")
    )
    test_name = _clean(
        _first(
            normalized,
            "test_name",
            "name",
            default=test_external_id or "Validation test",
        )
    )
    test = ValidationTest.objects.filter(
        integration=source_object.integration,
        external_id=test_external_id,
    ).first()
    if test is None:
        test = ValidationTest.objects.create(
            integration=source_object.integration,
            external_id=test_external_id or f"implicit:{source_object.external_id}",
            name=test_name,
        )

    technique_id = _technique_id(
        _first(normalized, "technique_id", "attack_technique", "attack_id")
    )
    technique = resolve_technique(technique_id) if technique_id else None
    if technique:
        test.techniques.add(technique)

    detection_external_id = _clean(
        _first(
            normalized,
            "detection_id",
            "rule_id",
            "detection_external_id",
        )
    )
    detection = None
    if detection_external_id:
        detection = DetectionRule.objects.filter(
            integration=source_object.integration,
            external_id=detection_external_id,
        ).first()
        if detection is None:
            detection = DetectionRule.objects.filter(external_id=detection_external_id).first()

    outcome = _validation_outcome(
        _first(normalized, "outcome", "status", default="not_run")
    )
    if outcome not in dict(ValidationResult.Outcome.choices):
        outcome = ValidationResult.Outcome.ERROR

    raw_evidence = normalized.get("evidence")
    if isinstance(raw_evidence, Mapping):
        evidence = dict(raw_evidence)
    else:
        evidence = {
            "source": source_object.integration.slug,
            "detail": _clean(raw_evidence),
        }
    result, _ = ValidationResult.objects.update_or_create(
        source_object=source_object,
        defaults={
            "test": test,
            "technique": technique,
            "detection_rule": detection,
            "outcome": outcome,
            "executed_at": _datetime(
                _first(normalized, "executed_at", "execution_date")
            )
            or source_object.source_updated_at,
            "summary": _clean(_first(normalized, "summary", "notes", "evidence")),
            "evidence": evidence,
        },
    )
    return result


def project_threat_report(source_object: ExternalObject) -> ThreatReport:
    normalized = source_object.normalized
    external_id = _clean(
        _first(normalized, "report_id", "external_id", default=source_object.external_id)
    )
    title = _clean(_first(normalized, "title", "name", default=external_id))
    try:
        confidence = max(0, min(int(_first(normalized, "confidence", default=50)), 100))
    except (TypeError, ValueError):
        confidence = 50
    marking = _clean(_first(normalized, "tlp", "marking")).lower()
    tlp = marking.removeprefix("tlp:")[:32]
    report, _ = ThreatReport.objects.update_or_create(
        source_object=source_object,
        defaults={
            "integration": source_object.integration,
            "external_id": external_id[:500],
            "title": title[:700],
            "summary": _clean(_first(normalized, "summary", "description")),
            "source_name": _clean(_first(normalized, "source_name", "publisher"))[:255],
            "source_url": _clean(_first(normalized, "source_url", "url"))[:1000],
            "published_at": _datetime(
                _first(normalized, "published_at", "created_at")
            )
            or source_object.source_updated_at,
            "confidence": confidence,
            "tlp": tlp,
            "targeted_industries": _list(
                _first(normalized, "targeted_industries", "industries", default=[])
            ),
            "metadata": dict(_mapping(normalized.get("metadata"))),
        },
    )

    default_review = _clean(
        source_object.integration.configuration.get("default_review_status", "pending")
    ).lower()
    if default_review not in dict(ThreatReportTechnique.ReviewStatus.choices):
        default_review = ThreatReportTechnique.ReviewStatus.PENDING

    ThreatReportTechnique.objects.filter(report=report).delete()
    for item in _list(
        _first(normalized, "techniques", "attack_techniques", default=[])
    ):
        if isinstance(item, Mapping):
            identifier = _first(
                item,
                "technique_id",
                "attack_id",
                "id",
                "external_id",
            )
            name = _clean(item.get("name"))
            evidence_excerpt = _clean(_first(item, "evidence_excerpt", "evidence"))
            review_status = _clean(item.get("review_status") or default_review).lower()
            try:
                link_confidence = max(
                    0,
                    min(int(item.get("confidence") or confidence), 100),
                )
            except (TypeError, ValueError):
                link_confidence = confidence
        else:
            identifier = item
            name = ""
            evidence_excerpt = ""
            review_status = default_review
            link_confidence = confidence
        technique_id = _technique_id(identifier)
        if not technique_id:
            continue
        if review_status not in dict(ThreatReportTechnique.ReviewStatus.choices):
            review_status = ThreatReportTechnique.ReviewStatus.PENDING
        ThreatReportTechnique.objects.create(
            report=report,
            technique=resolve_technique(technique_id, name),
            confidence=link_confidence,
            review_status=review_status,
            evidence_excerpt=evidence_excerpt,
        )

    ThreatReportVulnerability.objects.filter(report=report).delete()
    for item in _list(_first(normalized, "vulnerabilities", "cves", default=[])):
        if isinstance(item, Mapping):
            identifier = _first(item, "cve_id", "id")
            evidence_excerpt = _clean(_first(item, "evidence_excerpt", "evidence"))
            payload = dict(item)
            payload.setdefault("cve_id", identifier)
        else:
            identifier = item
            evidence_excerpt = ""
            payload = {"cve_id": identifier}
        if not _cve(identifier):
            continue
        ThreatReportVulnerability.objects.create(
            report=report,
            vulnerability=resolve_vulnerability(payload),
            evidence_excerpt=evidence_excerpt,
        )

    Observable.objects.filter(report=report).delete()
    for item in _list(normalized.get("observables")):
        if not isinstance(item, Mapping):
            continue
        observable_type = _clean(_first(item, "type", "observable_type"))
        value = _clean(item.get("value"))
        if not observable_type or not value:
            continue
        try:
            observable_confidence = max(
                0,
                min(int(item.get("confidence") or confidence), 100),
            )
        except (TypeError, ValueError):
            observable_confidence = confidence
        Observable.objects.create(
            report=report,
            observable_type=observable_type[:64],
            value=value[:2000],
            confidence=observable_confidence,
            first_seen_at=_datetime(item.get("first_seen_at")),
            last_seen_at=_datetime(item.get("last_seen_at")),
            metadata=dict(_mapping(item.get("metadata"))),
        )
    return report


PROJECTORS = {
    "asset": project_asset,
    "software_installation": project_software_installation,
    "vulnerability": project_vulnerability,
    "vulnerability_finding": project_vulnerability_finding,
    "attack_technique": project_attack_technique,
    "detection_rule": project_detection_rule,
    "telemetry_source": project_telemetry_source,
    "validation_test": project_validation_test,
    "validation_result": project_validation_result,
    "threat_report": project_threat_report,
}


@transaction.atomic
def materialize_external_object(source_object: ExternalObject) -> Any | None:
    projector = PROJECTORS.get(source_object.object_type)
    if projector is None:
        return None
    return projector(source_object)
