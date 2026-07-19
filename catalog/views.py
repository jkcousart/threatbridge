from __future__ import annotations

import uuid

from django.db.models import Count, IntegerField, OuterRef, Prefetch, Q, Subquery, Value
from django.db.models.functions import Coalesce
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from integrations.adapters.base import SourceRecord
from integrations.models import Integration
from integrations.services import ingest_source_record
from threatbridge.authorization import HasNamedPermission, Permissions

from .models import (
    Assessment,
    Asset,
    SecurityAuditEvent,
    SoftwareInstallation,
    SoftwareProduct,
    ThreatReport,
    ThreatReportTechnique,
    Vulnerability,
    VulnerabilityFinding,
)
from .provenance import (
    active_assessments,
    active_attack_techniques,
    active_detection_rules,
    active_telemetry_sources,
    active_validation_results,
    active_validation_tests,
)
from .serializers import (
    AssessmentSerializer,
    AssetSerializer,
    AttackTechniqueSerializer,
    DetectionRuleSerializer,
    ManualThreatReportSerializer,
    SecurityAuditEventSerializer,
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
from .services.review import transition_attack_mapping_review


class AssetViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Asset.objects.filter(
            sources__source_object__is_deleted=False
        ).distinct().annotate(
            software_count=Count(
                "software_installations",
                filter=Q(software_installations__source_object__is_deleted=False),
                distinct=True,
            ),
            open_vulnerability_count=Count(
                "vulnerability_findings",
                filter=Q(
                    vulnerability_findings__status="open",
                    vulnerability_findings__source_object__is_deleted=False,
                ),
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
        return queryset.order_by("id")


class SoftwareProductViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SoftwareProduct.objects.filter(
        Q(installations__source_object__is_deleted=False)
        | Q(vulnerability_findings__source_object__is_deleted=False)
    ).distinct()
    serializer_class = SoftwareProductSerializer
    permission_classes = [IsAuthenticated]


class SoftwareInstallationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SoftwareInstallationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = SoftwareInstallation.objects.filter(
            source_object__is_deleted=False
        ).select_related(
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
        return queryset.order_by("id")


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = Vulnerability.objects.filter(
            sources__source_object__is_deleted=False
        ).distinct().annotate(
            open_finding_count=Count(
                "findings",
                filter=Q(
                    findings__status="open",
                    findings__source_object__is_deleted=False,
                ),
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
        queryset = VulnerabilityFinding.objects.filter(
            source_object__is_deleted=False
        ).select_related(
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
        queryset = active_attack_techniques().annotate(
            detection_count=Count(
                "detection_rules",
                filter=Q(
                    detection_rules__enabled=True,
                    detection_rules__source_object__is_deleted=False,
                ),
                distinct=True,
            )
        )
        technique_id = self.request.query_params.get("technique_id")
        if technique_id:
            queryset = queryset.filter(technique_id__iexact=technique_id)
        return queryset


class TelemetrySourceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = active_telemetry_sources().select_related("integration")
    serializer_class = TelemetrySourceSerializer
    permission_classes = [IsAuthenticated]


class DetectionRuleViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DetectionRuleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = active_detection_rules().select_related(
            "integration"
        ).prefetch_related(
            Prefetch(
                "techniques",
                queryset=active_attack_techniques(),
                to_attr="active_techniques",
            ),
            Prefetch(
                "telemetry_sources",
                queryset=active_telemetry_sources(),
                to_attr="active_telemetry_sources",
            ),
        )
        technique_id = self.request.query_params.get("technique_id")
        enabled = self.request.query_params.get("enabled")
        if technique_id:
            queryset = queryset.filter(techniques__technique_id__iexact=technique_id)
        if enabled in {"true", "false"}:
            queryset = queryset.filter(enabled=enabled == "true")
        return queryset.distinct()


class ValidationTestViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = active_validation_tests().select_related("integration").prefetch_related(
        Prefetch(
            "techniques",
            queryset=active_attack_techniques(),
            to_attr="active_techniques",
        )
    )
    serializer_class = ValidationTestSerializer
    permission_classes = [IsAuthenticated]


class ValidationResultViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = active_validation_results().select_related(
        "test",
        "technique",
        "detection_rule",
    )
    serializer_class = ValidationResultSerializer
    permission_classes = [IsAuthenticated]


class ThreatReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ThreatReportSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.action in {"assess", "manual"}:
            return [HasNamedPermission()]
        return super().get_permissions()

    def get_required_permission(self):
        return {
            "assess": Permissions.RUN_ASSESSMENTS,
            "manual": Permissions.IMPORT_SOURCE_FILES,
        }.get(self.action)

    def get_queryset(self):
        active_assessment_counts = (
            active_assessments(Assessment.objects.filter(report_id=OuterRef("pk")))
            .values("report_id")
            .annotate(total=Count("pk"))
            .values("total")
        )
        queryset = (
            ThreatReport.objects.filter(source_object__is_deleted=False)
            .select_related("integration")
            .prefetch_related(
                "technique_links__technique",
                "vulnerability_links__vulnerability",
                "observables",
            )
            .annotate(
                assessment_count=Coalesce(
                    Subquery(active_assessment_counts, output_field=IntegerField()),
                    Value(0),
                )
            )
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
        return queryset.order_by("id")

    @action(detail=True, methods=["post"])
    def assess(self, request, pk=None):
        report = self.get_object()
        assessment = generate_assessment(
            report,
            actor=request.user,
            origin="rest:assessment",
        )
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
                "configuration": {},
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
            actor=request.user,
            origin="rest:manual_threat_report",
        )
        return Response(
            ThreatReportSerializer(projected).data,
            status=status.HTTP_201_CREATED,
        )


class ThreatReportTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ThreatReportTechnique.objects.filter(
        report__source_object__is_deleted=False
    ).select_related("report", "technique")
    serializer_class = ThreatReportTechniqueSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.action in {"approve", "reject"}:
            return [HasNamedPermission()]
        return super().get_permissions()

    def get_required_permission(self):
        return Permissions.REVIEW_ATTACK_MAPPINGS

    def _review(self, request, state):
        mapping = self.get_object()
        try:
            reviewed = transition_attack_mapping_review(
                mapping,
                new_state=state,
                actor=request.user,
                reason=request.data.get("reason", ""),
                origin=f"rest:attack_mapping_{state}",
            )
        except ValueError as exc:
            return Response(
                {"reason": [str(exc)]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(self.get_serializer(reviewed).data)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        return self._review(request, ThreatReportTechnique.ReviewStatus.APPROVED)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        return self._review(request, ThreatReportTechnique.ReviewStatus.REJECTED)


class AssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AssessmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = active_assessments().select_related(
            "report", "created_by"
        ).prefetch_related(
            "findings__technique",
            "findings__vulnerability",
        )
        report_id = self.request.query_params.get("report")
        if report_id:
            queryset = queryset.filter(report_id=report_id)
        return queryset


class SecurityAuditEventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SecurityAuditEvent.objects.select_related("actor")
    serializer_class = SecurityAuditEventSerializer
    permission_classes = [HasNamedPermission]

    def get_required_permission(self):
        return Permissions.VIEW_SECURITY_AUDIT_EVENTS
