from __future__ import annotations

import uuid

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from integrations.adapters.base import SourceRecord
from integrations.models import Integration
from integrations.services import ingest_source_record

from .models import (
    Assessment,
    Asset,
    AttackTechnique,
    DetectionRule,
    SoftwareInstallation,
    SoftwareProduct,
    TelemetrySource,
    ThreatReport,
    ThreatReportTechnique,
    ValidationResult,
    ValidationTest,
    Vulnerability,
    VulnerabilityFinding,
)
from .serializers import (
    AssessmentSerializer,
    AssetSerializer,
    AttackTechniqueSerializer,
    DetectionRuleSerializer,
    ManualThreatReportSerializer,
    SoftwareInstallationSerializer,
    SoftwareProductSerializer,
    TelemetrySourceSerializer,
    ThreatReportSerializer,
    ThreatReportTechniqueSerializer,
    ValidationResultSerializer,
    ValidationTestSerializer,
    VulnerabilityFindingSerializer,
    VulnerabilitySerializer,
)
from .services.assess import generate_assessment


class AssetViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Asset.objects.annotate(
            software_count=Count("software_installations", distinct=True),
            open_vulnerability_count=Count(
                "vulnerability_findings",
                filter=Q(vulnerability_findings__status="open"),
                distinct=True,
            ),
        )
        search = self.request.query_params.get("search")
        criticality = self.request.query_params.get("criticality")
        if search:
            queryset = queryset.filter(
                Q(display_name__icontains=search)
                | Q(hostname__icontains=search)
                | Q(fqdn__icontains=search)
                | Q(business_service__icontains=search)
            )
        if criticality:
            queryset = queryset.filter(criticality=criticality)
        return queryset


class SoftwareProductViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SoftwareProduct.objects.all()
    serializer_class = SoftwareProductSerializer
    permission_classes = [IsAuthenticated]


class SoftwareInstallationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SoftwareInstallationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = SoftwareInstallation.objects.select_related(
            "asset",
            "product",
            "source_object__integration",
        )
        asset_id = self.request.query_params.get("asset")
        product_id = self.request.query_params.get("product")
        if asset_id:
            queryset = queryset.filter(asset_id=asset_id)
        if product_id:
            queryset = queryset.filter(product_id=product_id)
        return queryset


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Vulnerability.objects.annotate(
            open_finding_count=Count(
                "findings",
                filter=Q(findings__status="open"),
                distinct=True,
            )
        )
        cve_id = self.request.query_params.get("cve_id")
        known_exploited = self.request.query_params.get("known_exploited")
        if cve_id:
            queryset = queryset.filter(cve_id__iexact=cve_id)
        if known_exploited in {"true", "false"}:
            queryset = queryset.filter(known_exploited=known_exploited == "true")
        return queryset


class VulnerabilityFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilityFindingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = VulnerabilityFinding.objects.select_related(
            "asset",
            "vulnerability",
            "product",
            "source_object__integration",
        )
        cve_id = self.request.query_params.get("cve_id")
        asset_id = self.request.query_params.get("asset")
        finding_status = self.request.query_params.get("status")
        if cve_id:
            queryset = queryset.filter(vulnerability__cve_id__iexact=cve_id)
        if asset_id:
            queryset = queryset.filter(asset_id=asset_id)
        if finding_status:
            queryset = queryset.filter(status=finding_status)
        return queryset


class AttackTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AttackTechniqueSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = AttackTechnique.objects.annotate(
            detection_count=Count(
                "detection_rules",
                filter=Q(detection_rules__enabled=True),
                distinct=True,
            )
        )
        technique_id = self.request.query_params.get("technique_id")
        if technique_id:
            queryset = queryset.filter(technique_id__iexact=technique_id)
        return queryset


class TelemetrySourceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = TelemetrySource.objects.select_related("integration")
    serializer_class = TelemetrySourceSerializer
    permission_classes = [IsAuthenticated]


class DetectionRuleViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DetectionRuleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = DetectionRule.objects.select_related("integration").prefetch_related(
            "techniques",
            "telemetry_sources",
        )
        technique_id = self.request.query_params.get("technique_id")
        enabled = self.request.query_params.get("enabled")
        if technique_id:
            queryset = queryset.filter(techniques__technique_id__iexact=technique_id)
        if enabled in {"true", "false"}:
            queryset = queryset.filter(enabled=enabled == "true")
        return queryset.distinct()


class ValidationTestViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ValidationTest.objects.select_related("integration").prefetch_related("techniques")
    serializer_class = ValidationTestSerializer
    permission_classes = [IsAuthenticated]


class ValidationResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ValidationResult.objects.select_related(
        "test",
        "technique",
        "detection_rule",
    )
    serializer_class = ValidationResultSerializer
    permission_classes = [IsAuthenticated]


class ThreatReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ThreatReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = (
            ThreatReport.objects.select_related("integration")
            .prefetch_related(
                "technique_links__technique",
                "vulnerability_links__vulnerability",
                "observables",
            )
            .annotate(assessment_count=Count("assessments", distinct=True))
        )
        integration = self.request.query_params.get("integration")
        search = self.request.query_params.get("search")
        if integration:
            queryset = queryset.filter(integration__slug=integration)
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search)
                | Q(summary__icontains=search)
                | Q(source_name__icontains=search)
            )
        return queryset

    @action(detail=True, methods=["post"])
    def assess(self, request, pk=None):
        report = self.get_object()
        assessment = generate_assessment(report, created_by=request.user)
        return Response(
            AssessmentSerializer(assessment).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=["post"], url_path="manual")
    def manual(self, request):
        serializer = ManualThreatReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        integration, _ = Integration.objects.get_or_create(
            slug="manual-threat-reports",
            defaults={
                "name": "Manual threat reports",
                "kind": Integration.Kind.THREAT_INTELLIGENCE,
                "adapter_path": "integrations.adapters.manual.ManualEntryAdapter",
                "configuration": {"default_review_status": "pending"},
            },
        )
        payload = dict(serializer.validated_data)
        payload.setdefault("published_at", timezone.now())
        if hasattr(payload.get("published_at"), "isoformat"):
            payload["published_at"] = payload["published_at"].isoformat()
        external_id = payload.pop("external_id", "") or str(uuid.uuid4())
        record = SourceRecord(
            external_id=external_id,
            object_type="threat_report",
            natural_key=str(payload["title"]),
            source_updated_at=timezone.now(),
            raw=dict(payload),
            normalized=payload,
        )
        _source, _disposition, _status, projected = ingest_source_record(
            integration,
            record,
            project=True,
        )
        return Response(
            ThreatReportSerializer(projected).data,
            status=status.HTTP_201_CREATED,
        )


class ThreatReportTechniqueViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    queryset = ThreatReportTechnique.objects.select_related("report", "technique")
    serializer_class = ThreatReportTechniqueSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "patch", "head", "options"]


class AssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssessmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Assessment.objects.select_related("report", "created_by").prefetch_related(
            "findings__technique",
            "findings__vulnerability",
        )
        report_id = self.request.query_params.get("report")
        if report_id:
            queryset = queryset.filter(report_id=report_id)
        return queryset
