from __future__ import annotations

from collections.abc import Iterable

from django.db.models import Q, QuerySet

from integrations.models import ExternalObject

from .models import (
    Assessment,
    Asset,
    AssetAlias,
    AttackTechnique,
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleTelemetry,
    GapFinding,
    Observable,
    SoftwareProduct,
    TelemetrySource,
    ValidationResult,
    ValidationTest,
    Vulnerability,
)


def active_assessments(queryset: QuerySet | None = None) -> QuerySet:
    """Return assessments whose complete provenance remains active."""

    queryset = queryset if queryset is not None else Assessment.objects.all()
    return queryset.filter(
        report__source_object__is_deleted=False,
        evidence_provenance_complete=True,
    ).exclude(evidence_sources__is_deleted=True)


def active_detection_rules(queryset: QuerySet | None = None) -> QuerySet:
    queryset = queryset if queryset is not None else DetectionRule.objects.all()
    return queryset.filter(source_object__is_deleted=False)


def active_telemetry_sources(queryset: QuerySet | None = None) -> QuerySet:
    queryset = queryset if queryset is not None else TelemetrySource.objects.all()
    return queryset.filter(
        Q(source_object__isnull=True) | Q(source_object__is_deleted=False)
    )


def active_attack_techniques(queryset: QuerySet | None = None) -> QuerySet:
    queryset = queryset if queryset is not None else AttackTechnique.objects.all()
    return queryset.filter(
        Q(source_object__isnull=True)
        | Q(source_object__is_deleted=False)
        | Q(threat_report_links__report__source_object__is_deleted=False)
    ).distinct()


def active_validation_tests(queryset: QuerySet | None = None) -> QuerySet:
    queryset = queryset if queryset is not None else ValidationTest.objects.all()
    return queryset.filter(
        Q(source_object__isnull=True) | Q(source_object__is_deleted=False)
    )


def active_validation_results(queryset: QuerySet | None = None) -> QuerySet:
    """Exclude results whose own or directly referenced provenance is deleted."""

    queryset = queryset if queryset is not None else ValidationResult.objects.all()
    return (
        queryset.filter(source_object__is_deleted=False)
        .filter(
            Q(test__source_object__isnull=True)
            | Q(test__source_object__is_deleted=False)
        )
        .filter(
            Q(detection_rule__isnull=True)
            | Q(detection_rule__source_object__is_deleted=False)
        )
        .distinct()
    )


def active_admin_queryset(model: type, queryset: QuerySet) -> QuerySet:
    """Apply active-provenance policy to every derived admin queryset."""

    if model is Asset:
        return queryset.filter(sources__source_object__is_deleted=False).distinct()
    if model is AssetAlias:
        return queryset.filter(
            asset__sources__source_object__is_deleted=False
        ).distinct()
    if model is SoftwareProduct:
        return queryset.filter(
            Q(installations__source_object__is_deleted=False)
            | Q(vulnerability_findings__source_object__is_deleted=False)
        ).distinct()
    if model is Vulnerability:
        return queryset.filter(sources__source_object__is_deleted=False).distinct()
    if model is AttackTechnique:
        return active_attack_techniques(queryset)
    if model is Assessment:
        return active_assessments(queryset)
    if model is ValidationResult:
        return active_validation_results(queryset)
    if model is GapFinding:
        return queryset.filter(assessment__in=active_assessments()).distinct()
    if model is Observable:
        return queryset.filter(report__source_object__is_deleted=False)
    if model is DetectionRuleTechnique:
        return queryset.filter(
            detection_rule__source_object__is_deleted=False,
            technique__in=active_attack_techniques(),
        ).distinct()
    if model is DetectionRuleTelemetry:
        return queryset.filter(
            detection_rule__source_object__is_deleted=False,
            telemetry_source__in=active_telemetry_sources(),
        ).distinct()
    if any(field.name == "source_object" for field in model._meta.fields):
        return queryset.filter(
            Q(source_object__isnull=True) | Q(source_object__is_deleted=False)
        )
    return queryset


def attach_active_assessment_provenance(
    assessment: Assessment,
    source_ids: Iterable[int],
) -> None:
    """Lock candidate evidence, attach only active rows, and record completeness."""

    expected_ids = {int(source_id) for source_id in source_ids}
    locked_sources = list(
        ExternalObject.all_objects.select_for_update().filter(pk__in=expected_ids)
    )
    active_ids = {
        source_object.pk for source_object in locked_sources if not source_object.is_deleted
    }
    assessment.evidence_sources.set(active_ids)
    assessment.evidence_provenance_complete = (
        len(locked_sources) == len(expected_ids) and active_ids == expected_ids
    )
