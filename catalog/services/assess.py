from __future__ import annotations

from collections import Counter
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from catalog.models import (
    Assessment,
    Criticality,
    GapFinding,
    ThreatReport,
    ThreatReportTechnique,
    ValidationResult,
    VulnerabilityFinding,
)
from catalog.provenance import (
    active_attack_techniques,
    active_detection_rules,
    active_telemetry_sources,
    active_validation_results,
    attach_active_assessment_provenance,
)
from catalog.services.audit import record_security_event
from integrations.models import ExternalObject
from threatbridge.authorization import Permissions, require_operation_permission


def _priority_rank(value: str) -> int:
    return {
        GapFinding.Priority.INFO: 0,
        GapFinding.Priority.LOW: 1,
        GapFinding.Priority.MEDIUM: 2,
        GapFinding.Priority.HIGH: 3,
        GapFinding.Priority.CRITICAL: 4,
    }.get(value, 0)


def _technique_finding(
    assessment: Assessment,
    link: ThreatReportTechnique,
) -> GapFinding:
    technique = link.technique
    detections = list(
        active_detection_rules(technique.detection_rules.filter(enabled=True))
        .select_related("integration")
        .prefetch_related("telemetry_sources")
    )

    required_telemetry: dict[str, bool | None] = {}
    for detection in detections:
        relations = detection.detectionruletelemetry_set.filter(
            Q(telemetry_source__source_object__isnull=True)
            | Q(telemetry_source__source_object__is_deleted=False)
        ).select_related("telemetry_source")
        for relation in relations:
            if relation.required:
                required_telemetry[relation.telemetry_source.name] = (
                    relation.telemetry_source.available
                )

    validations = (
        active_validation_results().filter(
            Q(technique=technique) | Q(detection_rule__in=detections),
        )
        .select_related("test", "detection_rule")
        .order_by("-executed_at", "-created_at")
    )
    latest = validations.first()
    missing = sorted(
        name for name, available in required_telemetry.items() if available is False
    )
    unknown = sorted(
        name for name, available in required_telemetry.items() if available is None
    )

    if not detections:
        state = GapFinding.State.DETECTION_MISSING
        priority = GapFinding.Priority.HIGH
        recommendation = (
            f"Create or map a detection for {technique.technique_id} and document "
            "its required telemetry."
        )
        rationale = (
            "The report references this technique, but no enabled detection rule is "
            "mapped to it."
        )
    elif missing:
        state = GapFinding.State.TELEMETRY_MISSING
        priority = GapFinding.Priority.HIGH
        recommendation = (
            "Restore or onboard the required telemetry before relying on the mapped "
            "detection rules."
        )
        rationale = (
            "Enabled detections exist, but required telemetry is unavailable: "
            + ", ".join(missing)
            + "."
        )
    elif latest is None:
        state = GapFinding.State.DETECTION_DOCUMENTED
        priority = GapFinding.Priority.MEDIUM
        recommendation = f"Execute an approved validation test for {technique.technique_id}."
        rationale = (
            "At least one enabled detection is mapped, but no validation evidence was found."
        )
    elif latest.outcome == ValidationResult.Outcome.FAILED:
        state = GapFinding.State.VALIDATION_FAILED
        priority = GapFinding.Priority.HIGH
        recommendation = (
            "Investigate the failed validation, confirm event ingestion, and retest after tuning."
        )
        rationale = "The most recent relevant validation did not produce the expected result."
    elif latest.outcome == ValidationResult.Outcome.PARTIAL:
        state = GapFinding.State.PARTIALLY_VALIDATED
        priority = GapFinding.Priority.MEDIUM
        recommendation = "Resolve the documented limitations and repeat the validation test."
        rationale = "The most recent relevant validation produced only partial evidence."
    elif latest.outcome == ValidationResult.Outcome.PASSED and unknown:
        state = GapFinding.State.VALIDATED_WITH_LIMITATIONS
        priority = GapFinding.Priority.LOW
        recommendation = "Confirm the availability state of all required telemetry sources."
        rationale = (
            "A validation passed, but some required telemetry sources have unknown availability."
        )
    elif latest.outcome == ValidationResult.Outcome.PASSED:
        state = GapFinding.State.VALIDATED
        priority = GapFinding.Priority.INFO
        recommendation = (
            "Retain evidence and repeat validation after material rule or telemetry changes."
        )
        rationale = (
            "The most recent relevant validation passed and no required telemetry is unavailable."
        )
    else:
        state = GapFinding.State.DETECTION_DOCUMENTED
        priority = GapFinding.Priority.MEDIUM
        recommendation = "Run or complete an approved validation test."
        rationale = (
            "Detection coverage is documented, but the latest validation is not a conclusive pass."
        )

    evidence: dict[str, Any] = {
        "report_mapping": {
            "confidence": link.confidence,
            "review_status": link.review_status,
            "excerpt": link.evidence_excerpt,
        },
        "detections": [
            {
                "id": detection.id,
                "external_id": detection.external_id,
                "name": detection.name,
                "source": detection.integration.slug,
                "severity": detection.severity,
            }
            for detection in detections
        ],
        "required_telemetry": required_telemetry,
        "latest_validation": (
            {
                "id": latest.id,
                "test": latest.test.name,
                "outcome": latest.outcome,
                "executed_at": latest.executed_at.isoformat()
                if latest.executed_at
                else None,
                "detection": latest.detection_rule.name
                if latest.detection_rule
                else None,
                "summary": latest.summary,
            }
            if latest
            else None
        ),
    }
    return GapFinding.objects.create(
        assessment=assessment,
        category=GapFinding.Category.TECHNIQUE,
        state=state,
        priority=priority,
        title=f"{technique.technique_id} - {technique.name}",
        technique=technique,
        recommendation=recommendation,
        rationale=rationale,
        evidence=evidence,
    )


def _vulnerability_finding(assessment: Assessment, report_link) -> GapFinding:
    vulnerability = report_link.vulnerability
    findings = list(
        VulnerabilityFinding.objects.filter(
            vulnerability=vulnerability,
            status=VulnerabilityFinding.Status.OPEN,
            source_object__is_deleted=False,
        ).select_related("asset", "product", "source_object__integration")
    )
    critical_count = sum(
        1 for finding in findings if finding.asset.criticality == Criticality.CRITICAL
    )
    high_value_count = sum(
        1
        for finding in findings
        if finding.asset.criticality in {Criticality.HIGH, Criticality.CRITICAL}
    )
    internet_exposed_count = sum(
        1 for finding in findings if finding.asset.internet_exposed is True
    )

    if not findings:
        state = GapFinding.State.EXPOSURE_NOT_FOUND
        priority = GapFinding.Priority.INFO
        recommendation = (
            "Continue monitoring and confirm that relevant asset sources remain current."
        )
        rationale = (
            "No open vulnerability finding currently matches this CVE in the normalized inventory."
        )
    else:
        state = GapFinding.State.EXPOSURE_CONFIRMED
        if critical_count and (
            vulnerability.known_exploited
            or (vulnerability.exploit_available and internet_exposed_count)
        ):
            priority = GapFinding.Priority.CRITICAL
        elif (
            critical_count
            or high_value_count
            or vulnerability.known_exploited
            or internet_exposed_count
        ):
            priority = GapFinding.Priority.HIGH
        else:
            priority = GapFinding.Priority.MEDIUM
        recommendation = (
            "Validate remediation ownership and timing, then document compensating "
            "detection coverage until exposure is removed."
        )
        rationale = (
            f"{len(findings)} open finding(s) match this report, including "
            f"{critical_count} critical asset(s) and {internet_exposed_count} "
            "internet-exposed asset(s)."
        )

    evidence = {
        "report_excerpt": report_link.evidence_excerpt,
        "known_exploited": vulnerability.known_exploited,
        "exploit_available": vulnerability.exploit_available,
        "severity": vulnerability.severity,
        "cvss_score": float(vulnerability.cvss_score)
        if vulnerability.cvss_score is not None
        else None,
        "assets": [
            {
                "id": finding.asset_id,
                "name": finding.asset.display_name,
                "criticality": finding.asset.criticality,
                "business_service": finding.asset.business_service,
                "internet_exposed": finding.asset.internet_exposed,
                "product": str(finding.product) if finding.product else None,
                "installed_version": finding.installed_version,
                "source": finding.source_object.integration.slug,
                "last_seen_at": finding.last_seen_at.isoformat()
                if finding.last_seen_at
                else None,
            }
            for finding in findings[:500]
        ],
        "asset_evidence_truncated": len(findings) > 500,
    }
    return GapFinding.objects.create(
        assessment=assessment,
        category=GapFinding.Category.VULNERABILITY,
        state=state,
        priority=priority,
        title=vulnerability.cve_id,
        vulnerability=vulnerability,
        affected_asset_count=len(findings),
        critical_asset_count=critical_count,
        recommendation=recommendation,
        rationale=rationale,
        evidence=evidence,
    )


def generate_assessment(
    report: ThreatReport,
    *,
    actor=None,
    origin: str,
    system: bool = False,
) -> Assessment:
    require_operation_permission(
        actor,
        Permissions.RUN_ASSESSMENTS,
        origin=origin,
        system=system,
    )
    failure: Exception | None = None

    with transaction.atomic():
        locked_source = (
            ExternalObject.all_objects.select_for_update()
            .select_related("integration")
            .get(pk=report.source_object_id)
        )
        if locked_source.is_deleted:
            raise ValueError("Deleted source evidence cannot be assessed.")
        report = ThreatReport.objects.select_related("source_object").get(
            pk=report.pk,
            source_object_id=locked_source.pk,
        )
        assessment = Assessment.objects.create(
            report=report,
            created_by=actor if getattr(actor, "is_authenticated", False) else None,
            origin=origin,
        )
        record_security_event(
            event_type="assessment.started",
            origin=origin,
            outcome="started",
            actor=actor,
            target_type="assessment",
            target_identifier=assessment.pk,
            metadata={"report_id": report.pk},
        )

        try:
            with transaction.atomic():
                technique_links = report.technique_links.filter(
                    review_status__in=[
                        ThreatReportTechnique.ReviewStatus.APPROVED,
                        ThreatReportTechnique.ReviewStatus.UNCERTAIN,
                    ]
                ).select_related("technique")
                vulnerability_links = report.vulnerability_links.select_related(
                    "vulnerability"
                )

                for link in technique_links:
                    _technique_finding(assessment, link)
                for link in vulnerability_links:
                    _vulnerability_finding(assessment, link)

                technique_ids = list(
                    technique_links.values_list("technique_id", flat=True)
                )
                vulnerability_ids = list(
                    vulnerability_links.values_list("vulnerability_id", flat=True)
                )
                source_ids = {locked_source.pk}

                detections = active_detection_rules().filter(
                    techniques__id__in=technique_ids
                )
                source_ids.update(
                    detections.values_list("source_object_id", flat=True)
                )

                validation_results = active_validation_results().filter(
                    Q(technique_id__in=technique_ids)
                    | Q(detection_rule__techniques__id__in=technique_ids)
                )
                source_ids.update(
                    validation_results.values_list("source_object_id", flat=True)
                )
                source_ids.update(
                    validation_results.exclude(test__source_object__isnull=True)
                    .values_list("test__source_object_id", flat=True)
                )

                source_ids.update(
                    active_attack_techniques()
                    .filter(
                        id__in=technique_ids,
                        source_object__is_deleted=False,
                    )
                    .exclude(source_object__isnull=True)
                    .values_list("source_object_id", flat=True)
                )
                source_ids.update(
                    active_telemetry_sources()
                    .filter(
                        detection_rules__in=detections,
                        source_object__is_deleted=False,
                    )
                    .exclude(source_object__isnull=True)
                    .values_list("source_object_id", flat=True)
                )
                source_ids.update(
                    ExternalObject.objects.filter(
                        vulnerability_finding_projection__vulnerability_id__in=(
                            vulnerability_ids
                        ),
                        vulnerability_finding_projection__status=(
                            VulnerabilityFinding.Status.OPEN
                        ),
                    ).values_list("id", flat=True)
                )
                source_ids.update(
                    ExternalObject.objects.filter(
                        vulnerability_projections__vulnerability_id__in=(
                            vulnerability_ids
                        )
                    ).values_list("id", flat=True)
                )
                source_ids.update(
                    ExternalObject.objects.filter(
                        asset_projection__asset__vulnerability_findings__vulnerability_id__in=(
                            vulnerability_ids
                        ),
                        asset_projection__asset__vulnerability_findings__status=(
                            VulnerabilityFinding.Status.OPEN
                        ),
                        asset_projection__asset__vulnerability_findings__source_object__is_deleted=(
                            False
                        ),
                    ).values_list("id", flat=True)
                )
                attach_active_assessment_provenance(assessment, source_ids)
                if not assessment.evidence_provenance_complete:
                    raise ValueError(
                        "Assessment provenance changed during execution; retry the assessment."
                    )

                findings = list(assessment.findings.all())
                states = Counter(finding.state for finding in findings)
                priorities = Counter(finding.priority for finding in findings)
                highest_priority = max(
                    (finding.priority for finding in findings),
                    key=_priority_rank,
                    default=GapFinding.Priority.INFO,
                )
                assessment.summary = {
                    "finding_count": len(findings),
                    "technique_count": sum(
                        1
                        for finding in findings
                        if finding.category == GapFinding.Category.TECHNIQUE
                    ),
                    "vulnerability_count": sum(
                        1
                        for finding in findings
                        if finding.category == GapFinding.Category.VULNERABILITY
                    ),
                    "pending_technique_reviews": report.technique_links.filter(
                        review_status=ThreatReportTechnique.ReviewStatus.PENDING
                    ).count(),
                    "states": dict(states),
                    "priorities": dict(priorities),
                    "highest_priority": highest_priority,
                }
                assessment.status = Assessment.Status.SUCCEEDED
                assessment.completed_at = timezone.now()
                assessment.save(
                    update_fields=[
                        "summary",
                        "status",
                        "completed_at",
                        "evidence_provenance_complete",
                        "updated_at",
                    ]
                )
        except Exception as exc:
            failure = exc
            assessment.status = Assessment.Status.FAILED
            assessment.completed_at = timezone.now()
            assessment.error_summary = f"{type(exc).__name__}: assessment failed"
            assessment.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "error_summary",
                    "updated_at",
                ]
            )
            record_security_event(
                event_type="assessment.completed",
                origin=origin,
                outcome="failed",
                actor=actor,
                target_type="assessment",
                target_identifier=assessment.pk,
                metadata={"report_id": report.pk, "error_type": type(exc).__name__},
            )
        else:
            record_security_event(
                event_type="assessment.completed",
                origin=origin,
                outcome="succeeded",
                actor=actor,
                target_type="assessment",
                target_identifier=assessment.pk,
                metadata={
                    "report_id": report.pk,
                    "finding_count": assessment.summary["finding_count"],
                },
            )

    if failure is not None:
        raise failure
    return assessment


run_assessment = generate_assessment
