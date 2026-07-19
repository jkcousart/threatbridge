from __future__ import annotations

from collections import Counter

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, IntegerField, OuterRef, Prefetch, Q, Subquery, Value
from django.db.models.functions import Coalesce
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from integrations.file_imports import create_file_import, inspect_uploaded_file
from integrations.forms import FILE_ADAPTER_PATHS, FileImportForm
from integrations.models import ExternalObject, Integration, SyncRun
from integrations.secrets import sanitized_connector_error
from integrations.services import run_integration_sync, test_integration
from threatbridge.authorization import Permissions, is_allowed, policy_required

from .models import (
    Assessment,
    Asset,
    DetectionRule,
    GapFinding,
    ThreatReport,
    ThreatReportTechnique,
    VulnerabilityFinding,
)
from .provenance import active_assessments, active_detection_rules
from .services.assess import generate_assessment
from .services.review import REVIEW_DECISIONS, transition_attack_mapping_review

PRIORITY_RANK = {
    GapFinding.Priority.CRITICAL: 0,
    GapFinding.Priority.HIGH: 1,
    GapFinding.Priority.MEDIUM: 2,
    GapFinding.Priority.LOW: 3,
    GapFinding.Priority.INFO: 4,
}


def _profile_initial(integration: Integration) -> dict:
    configuration = integration.configuration or {}
    return {
        "integration": integration.pk,
        "name": integration.name,
        "object_type": (
            "mixed" if configuration.get("envelope") else configuration.get("object_type", "auto")
        ),
        "id_fields": ",".join(
            configuration.get("id_fields")
            or ([configuration.get("id_field")] if configuration.get("id_field") else [])
        ),
        "records_key": configuration.get("records_key", ""),
        "natural_key_field": configuration.get("natural_key_field", ""),
        "updated_at_field": configuration.get("updated_at_field", ""),
        "delimiter": configuration.get("delimiter", ""),
        "field_map": configuration.get("field_map", {}),
        "strict_records": configuration.get("strict_records", False),
        "sync_now": True,
    }


@policy_required(Permissions.IMPORT_SOURCE_FILES)
def file_import_new(request: HttpRequest) -> HttpResponse:
    can_manage_profiles = is_allowed(
        request.user,
        Permissions.VIEW_INTEGRATIONS,
    ) and is_allowed(request.user, Permissions.CONFIGURE_INTEGRATIONS)
    initial: dict = {"object_type": "auto", "sync_now": True}
    profile_id = request.GET.get("profile")
    if profile_id and can_manage_profiles:
        profile = Integration.objects.filter(
            pk=profile_id,
            adapter_path__in=FILE_ADAPTER_PATHS,
        ).first()
        if profile:
            initial.update(_profile_initial(profile))

    if request.method == "POST":
        form = FileImportForm(
            request.POST,
            request.FILES,
            allow_existing_profiles=can_manage_profiles,
        )
        if form.is_valid():
            data = form.cleaned_data
            try:
                result = create_file_import(
                    uploaded_file=data["file"],
                    name=data.get("name", ""),
                    object_type=data.get("object_type", "auto"),
                    id_fields=data.get("id_fields", ""),
                    records_key=data.get("records_key", ""),
                    natural_key_field=data.get("natural_key_field", ""),
                    updated_at_field=data.get("updated_at_field", ""),
                    field_map=data.get("field_map", {}),
                    delimiter=data.get("delimiter", ""),
                    strict_records=data.get("strict_records", False),
                    sync_now=data.get("sync_now", True),
                    integration=data.get("integration"),
                    actor=request.user,
                    origin="browser:file_import",
                )
            except Exception as exc:
                form.add_error(None, sanitized_connector_error(exc))
            else:
                run = result.run
                if run:
                    message = (
                        f"{result.integration.name}: imported {run.records_accepted} of "
                        f"{run.records_received} records; projected {run.records_projected}."
                    )
                    if run.records_rejected or run.projection_failures:
                        messages.warning(request, message)
                    else:
                        messages.success(request, message)
                else:
                    messages.success(
                        request,
                        f"{result.integration.name}: upload saved and ready to synchronize.",
                    )
                return redirect(
                    "web-integration-list" if can_manage_profiles else "dashboard"
                )
    else:
        form = FileImportForm(
            initial=initial,
            allow_existing_profiles=can_manage_profiles,
        )

    profiles = (
        [
            {"id": integration.pk, **_profile_initial(integration)}
            for integration in Integration.objects.filter(
                adapter_path__in=FILE_ADAPTER_PATHS
            ).order_by("name")
        ]
        if can_manage_profiles
        else []
    )
    return render(
        request,
        "catalog/import_file.html",
        {
            "form": form,
            "profiles": profiles,
            "max_upload_mb": round(
                getattr(settings, "THREATBRIDGE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)
                / 1024
                / 1024,
                1,
            ),
        },
    )


@require_POST
@policy_required(Permissions.IMPORT_SOURCE_FILES)
def file_import_preview(request: HttpRequest) -> JsonResponse:
    uploaded_file = request.FILES.get("file")
    if uploaded_file is None:
        return JsonResponse({"error": "Choose a file before previewing."}, status=400)
    try:
        inspection = inspect_uploaded_file(
            uploaded_file,
            records_key=request.POST.get("records_key", ""),
            delimiter=request.POST.get("delimiter", ""),
            object_type=request.POST.get("object_type", "auto"),
        )
    except (OSError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except Exception:
        return JsonResponse({"error": "The file could not be inspected."}, status=400)
    return JsonResponse(inspection.as_dict())


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    can_view_integrations = is_allowed(request.user, Permissions.VIEW_INTEGRATIONS)
    latest_assessment = (
        active_assessments(
            Assessment.objects.filter(status=Assessment.Status.SUCCEEDED)
        )
        .select_related("report")
        .first()
    )
    priority_counts = Counter()
    state_counts = Counter()
    if latest_assessment:
        priority_counts.update(
            latest_assessment.findings.values_list("priority", flat=True)
        )
        state_counts.update(latest_assessment.findings.values_list("state", flat=True))

    context = {
        "asset_count": Asset.objects.filter(
            sources__source_object__is_deleted=False
        ).distinct().count(),
        "open_vulnerability_count": VulnerabilityFinding.objects.filter(
            status="open",
            source_object__is_deleted=False,
        ).count(),
        "enabled_detection_count": DetectionRule.objects.filter(
            enabled=True,
            source_object__is_deleted=False,
        ).count(),
        "report_count": ThreatReport.objects.filter(source_object__is_deleted=False).count(),
        "integration_count": Integration.objects.count() if can_view_integrations else 0,
        "unhealthy_integration_count": (
            Integration.objects.exclude(health=Integration.Health.HEALTHY).count()
            if can_view_integrations
            else 0
        ),
        "pending_review_count": ThreatReportTechnique.objects.filter(
            review_status=ThreatReportTechnique.ReviewStatus.PENDING,
            report__source_object__is_deleted=False,
        ).count(),
        "latest_reports": ThreatReport.objects.filter(
            source_object__is_deleted=False
        ).select_related("integration")[:6],
        "latest_runs": (
            SyncRun.objects.select_related("integration")[:6]
            if can_view_integrations
            else []
        ),
        "can_view_integrations": can_view_integrations,
        "latest_assessment": latest_assessment,
        "priority_counts": priority_counts,
        "state_counts": state_counts,
    }
    return render(request, "catalog/dashboard.html", context)


@policy_required(Permissions.VIEW_INTEGRATIONS)
def integration_list(request: HttpRequest) -> HttpResponse:
    integrations = Integration.objects.annotate(
        object_count=Count(
            "external_objects",
            filter=Q(external_objects__is_deleted=False),
            distinct=True,
        ),
        run_count=Count("sync_runs", distinct=True),
    ).prefetch_related("sync_runs")
    return render(
        request,
        "catalog/integrations.html",
        {"integrations": integrations},
    )


@require_POST
@policy_required(Permissions.VIEW_INTEGRATIONS)
@policy_required(Permissions.TEST_INTEGRATIONS)
def integration_test(request: HttpRequest, pk: int) -> HttpResponse:
    integration = get_object_or_404(Integration, pk=pk)
    try:
        result = test_integration(
            integration,
            actor=request.user,
            origin="browser:integration_test",
        )
        if result.get("ok", True):
            messages.success(request, f"{integration.name}: connection test succeeded.")
        else:
            messages.warning(request, f"{integration.name}: connection test was degraded.")
    except Exception as exc:
        messages.error(request, f"{integration.name}: {sanitized_connector_error(exc)}")
    return redirect("web-integration-list")


@require_POST
@policy_required(Permissions.VIEW_INTEGRATIONS)
@policy_required(Permissions.SYNCHRONIZE_INTEGRATIONS)
def integration_sync(request: HttpRequest, pk: int) -> HttpResponse:
    integration = get_object_or_404(Integration, pk=pk)
    try:
        run = run_integration_sync(
            integration,
            actor=request.user,
            origin="browser:integration_sync",
        )
        messages.success(
            request,
            (
                f"{integration.name}: {run.status}; received {run.records_received}, "
                f"projected {run.records_projected}, rejected {run.records_rejected}."
            ),
        )
    except Exception as exc:
        messages.error(request, f"{integration.name}: {sanitized_connector_error(exc)}")
    return redirect("web-integration-list")


@policy_required(Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE)
def source_evidence_list(request: HttpRequest) -> HttpResponse:
    include_deleted = request.GET.get("include_deleted") == "true" and is_allowed(
        request.user,
        Permissions.VIEW_DELETED_SOURCE_EVIDENCE,
    )
    manager = ExternalObject.all_objects if include_deleted else ExternalObject.objects
    objects = manager.select_related("integration")
    integration = request.GET.get("integration", "")
    object_type = request.GET.get("object_type", "")
    projection_status = request.GET.get("projection_status", "")
    query = request.GET.get("q", "")
    if integration:
        objects = objects.filter(integration__slug=integration)
    if object_type:
        objects = objects.filter(object_type=object_type)
    if projection_status:
        objects = objects.filter(projection_status=projection_status)
    if query:
        objects = objects.filter(
            Q(external_id__icontains=query)
            | Q(natural_key__icontains=query)
            | Q(normalized__icontains=query)
        )
    objects = objects[:250]
    return render(
        request,
        "catalog/source_evidence.html",
        {
            "objects": objects,
            "integrations": Integration.objects.all(),
            "object_types": manager.order_by()
            .values_list("object_type", flat=True)
            .distinct(),
            "projection_choices": ExternalObject.ProjectionStatus.choices,
            "filters": {
                "integration": integration,
                "object_type": object_type,
                "projection_status": projection_status,
                "q": query,
                "include_deleted": include_deleted,
            },
        },
    )


@login_required
def threat_report_list(request: HttpRequest) -> HttpResponse:
    active_assessment_counts = (
        active_assessments(Assessment.objects.filter(report_id=OuterRef("pk")))
        .values("report_id")
        .annotate(total=Count("pk"))
        .values("total")
    )
    reports = (
        ThreatReport.objects.filter(source_object__is_deleted=False)
        .select_related("integration")
        .annotate(
            technique_count=Count("technique_links", distinct=True),
            vulnerability_count=Count("vulnerability_links", distinct=True),
            assessment_count=Coalesce(
                Subquery(active_assessment_counts, output_field=IntegerField()),
                Value(0),
            ),
            pending_count=Count(
                "technique_links",
                filter=Q(
                    technique_links__review_status=ThreatReportTechnique.ReviewStatus.PENDING
                ),
                distinct=True,
            ),
        )
    )
    query = request.GET.get("q", "")
    if query:
        reports = reports.filter(
            Q(title__icontains=query)
            | Q(summary__icontains=query)
            | Q(source_name__icontains=query)
        )
    return render(
        request,
        "catalog/reports.html",
        {"reports": reports[:250], "query": query},
    )


@login_required
def threat_report_detail(request: HttpRequest, pk: int) -> HttpResponse:
    report = get_object_or_404(
        ThreatReport.objects.filter(source_object__is_deleted=False)
        .select_related("integration")
        .prefetch_related(
            Prefetch(
                "technique_links__technique__detection_rules",
                queryset=active_detection_rules(),
            ),
            "vulnerability_links__vulnerability",
            "observables",
        ),
        pk=pk,
    )
    report_assessments = active_assessments(report.assessments.all())
    assessment_count = report_assessments.count()
    assessments = report_assessments[:10]
    return render(
        request,
        "catalog/report_detail.html",
        {
            "report": report,
            "assessments": assessments,
            "assessment_count": assessment_count,
            "review_choices": [
                choice
                for choice in ThreatReportTechnique.ReviewStatus.choices
                if choice[0] in REVIEW_DECISIONS
            ],
        },
    )


@require_POST
@policy_required(Permissions.REVIEW_ATTACK_MAPPINGS)
def review_technique(request: HttpRequest, pk: int) -> HttpResponse:
    link = get_object_or_404(
        ThreatReportTechnique.objects.filter(
            report__source_object__is_deleted=False
        ).select_related("report", "technique"),
        pk=pk,
    )
    status_value = request.POST.get("review_status", "")
    try:
        link = transition_attack_mapping_review(
            link,
            new_state=status_value,
            actor=request.user,
            reason=request.POST.get("reason", ""),
            origin="browser:attack_mapping_review",
        )
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("web-threat-report-detail", pk=link.report_id)
    messages.success(
        request,
        f"{link.technique.technique_id} marked {link.get_review_status_display().lower()}.",
    )
    return redirect("web-threat-report-detail", pk=link.report_id)


@require_POST
@policy_required(Permissions.RUN_ASSESSMENTS)
def assess_report(request: HttpRequest, pk: int) -> HttpResponse:
    report = get_object_or_404(
        ThreatReport.objects.filter(source_object__is_deleted=False),
        pk=pk,
    )
    try:
        assessment = generate_assessment(
            report,
            actor=request.user,
            origin="browser:assessment",
        )
        messages.success(
            request,
            f"Assessment completed with {assessment.summary.get('finding_count', 0)} findings.",
        )
        return redirect("web-assessment-detail", pk=assessment.pk)
    except Exception as exc:
        messages.error(request, f"Assessment failed: {type(exc).__name__}")
        return redirect("web-threat-report-detail", pk=report.pk)


@login_required
def assessment_detail(request: HttpRequest, pk) -> HttpResponse:
    assessment = get_object_or_404(
        active_assessments()
        .select_related("report", "created_by")
        .prefetch_related(
            "findings__technique",
            "findings__vulnerability",
        ),
        pk=pk,
    )
    findings = sorted(
        assessment.findings.all(),
        key=lambda finding: (
            PRIORITY_RANK.get(finding.priority, 99),
            finding.category,
            finding.title,
        ),
    )
    return render(
        request,
        "catalog/assessment_detail.html",
        {"assessment": assessment, "findings": findings},
    )
