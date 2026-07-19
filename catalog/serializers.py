from __future__ import annotations

from rest_framework import serializers

from .models import (
    Assessment,
    Asset,
    AttackTechnique,
    DetectionRule,
    GapFinding,
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


class AssetSerializer(serializers.ModelSerializer):
    software_count = serializers.IntegerField(read_only=True, required=False)
    open_vulnerability_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Asset
        fields = [
            "id",
            "canonical_key",
            "display_name",
            "hostname",
            "fqdn",
            "os_platform",
            "os_version",
            "environment",
            "business_service",
            "owner",
            "criticality",
            "internet_exposed",
            "last_seen_at",
            "metadata",
            "software_count",
            "open_vulnerability_count",
            "created_at",
            "updated_at",
        ]


class SoftwareProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareProduct
        fields = ["id", "vendor", "name", "cpe", "metadata", "created_at", "updated_at"]


class SoftwareInstallationSerializer(serializers.ModelSerializer):
    asset_name = serializers.CharField(source="asset.display_name", read_only=True)
    product_name = serializers.CharField(source="product.name", read_only=True)
    product_vendor = serializers.CharField(source="product.vendor", read_only=True)
    source_integration = serializers.CharField(
        source="source_object.integration.slug",
        read_only=True,
    )

    class Meta:
        model = SoftwareInstallation
        fields = [
            "id",
            "asset",
            "asset_name",
            "product",
            "product_vendor",
            "product_name",
            "version",
            "first_seen_at",
            "last_seen_at",
            "end_of_support_status",
            "end_of_support_date",
            "evidence",
            "source_integration",
        ]


class VulnerabilitySerializer(serializers.ModelSerializer):
    open_finding_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "cve_id",
            "title",
            "description",
            "severity",
            "cvss_score",
            "exploitability",
            "known_exploited",
            "exploit_available",
            "published_at",
            "modified_at",
            "metadata",
            "open_finding_count",
            "created_at",
            "updated_at",
        ]


class VulnerabilityFindingSerializer(serializers.ModelSerializer):
    cve_id = serializers.CharField(source="vulnerability.cve_id", read_only=True)
    asset_name = serializers.CharField(source="asset.display_name", read_only=True)
    product_name = serializers.SerializerMethodField()
    source_integration = serializers.CharField(
        source="source_object.integration.slug",
        read_only=True,
    )

    class Meta:
        model = VulnerabilityFinding
        fields = [
            "id",
            "asset",
            "asset_name",
            "vulnerability",
            "cve_id",
            "product",
            "product_name",
            "installed_version",
            "severity",
            "status",
            "first_seen_at",
            "last_seen_at",
            "remediation",
            "evidence",
            "source_integration",
        ]

    def get_product_name(self, obj: VulnerabilityFinding) -> str | None:
        return str(obj.product) if obj.product else None


class AttackTechniqueSerializer(serializers.ModelSerializer):
    detection_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = AttackTechnique
        fields = [
            "id",
            "technique_id",
            "name",
            "description",
            "tactics",
            "platforms",
            "data_sources",
            "revoked",
            "deprecated",
            "attack_version",
            "detection_count",
            "created_at",
            "updated_at",
        ]


class TelemetrySourceSerializer(serializers.ModelSerializer):
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)

    class Meta:
        model = TelemetrySource
        fields = [
            "id",
            "key",
            "name",
            "description",
            "available",
            "integration_slug",
            "metadata",
            "created_at",
            "updated_at",
        ]


class DetectionRuleSerializer(serializers.ModelSerializer):
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)
    techniques = AttackTechniqueSerializer(many=True, read_only=True)
    telemetry_sources = TelemetrySourceSerializer(many=True, read_only=True)

    class Meta:
        model = DetectionRule
        fields = [
            "id",
            "integration_slug",
            "external_id",
            "name",
            "description",
            "query",
            "enabled",
            "severity",
            "owner",
            "source_updated_at",
            "techniques",
            "telemetry_sources",
            "metadata",
            "created_at",
            "updated_at",
        ]


class ValidationTestSerializer(serializers.ModelSerializer):
    techniques = AttackTechniqueSerializer(many=True, read_only=True)
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)

    class Meta:
        model = ValidationTest
        fields = [
            "id",
            "integration_slug",
            "external_id",
            "name",
            "description",
            "procedure",
            "enabled",
            "techniques",
            "metadata",
            "created_at",
            "updated_at",
        ]


class ValidationResultSerializer(serializers.ModelSerializer):
    test_name = serializers.CharField(source="test.name", read_only=True)
    technique_id = serializers.CharField(source="technique.technique_id", read_only=True)
    detection_name = serializers.CharField(source="detection_rule.name", read_only=True)

    class Meta:
        model = ValidationResult
        fields = [
            "id",
            "test",
            "test_name",
            "technique",
            "technique_id",
            "detection_rule",
            "detection_name",
            "outcome",
            "executed_at",
            "summary",
            "evidence",
            "created_at",
            "updated_at",
        ]


class ThreatReportTechniqueSerializer(serializers.ModelSerializer):
    technique_id = serializers.CharField(source="technique.technique_id", read_only=True)
    technique_name = serializers.CharField(source="technique.name", read_only=True)

    class Meta:
        model = ThreatReportTechnique
        fields = [
            "id",
            "technique",
            "technique_id",
            "technique_name",
            "confidence",
            "review_status",
            "evidence_excerpt",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "technique",
            "technique_id",
            "technique_name",
            "confidence",
            "evidence_excerpt",
            "created_at",
            "updated_at",
        ]


class ThreatReportVulnerabilitySerializer(serializers.ModelSerializer):
    cve_id = serializers.CharField(source="vulnerability.cve_id", read_only=True)
    severity = serializers.CharField(source="vulnerability.severity", read_only=True)

    class Meta:
        model = ThreatReportVulnerability
        fields = ["id", "vulnerability", "cve_id", "severity", "evidence_excerpt"]


class ObservableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Observable
        fields = [
            "id",
            "observable_type",
            "value",
            "confidence",
            "first_seen_at",
            "last_seen_at",
            "metadata",
        ]


class ThreatReportSerializer(serializers.ModelSerializer):
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)
    technique_links = ThreatReportTechniqueSerializer(many=True, read_only=True)
    vulnerability_links = ThreatReportVulnerabilitySerializer(many=True, read_only=True)
    observables = ObservableSerializer(many=True, read_only=True)
    assessment_count = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = ThreatReport
        fields = [
            "id",
            "integration_slug",
            "external_id",
            "title",
            "summary",
            "source_name",
            "source_url",
            "published_at",
            "confidence",
            "tlp",
            "targeted_industries",
            "metadata",
            "technique_links",
            "vulnerability_links",
            "observables",
            "assessment_count",
            "created_at",
            "updated_at",
        ]


class ManualThreatReportSerializer(serializers.Serializer):
    external_id = serializers.CharField(max_length=500, required=False, allow_blank=True)
    title = serializers.CharField(max_length=700)
    summary = serializers.CharField(required=False, allow_blank=True)
    source_name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    source_url = serializers.URLField(max_length=1000, required=False, allow_blank=True)
    published_at = serializers.DateTimeField(required=False)
    confidence = serializers.IntegerField(min_value=0, max_value=100, default=50)
    tlp = serializers.ChoiceField(
        choices=["clear", "green", "amber", "amber+strict", "red"],
        default="clear",
    )
    targeted_industries = serializers.ListField(
        child=serializers.CharField(max_length=255),
        required=False,
        default=list,
    )
    techniques = serializers.ListField(child=serializers.DictField(), required=False, default=list)
    vulnerabilities = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        default=list,
    )
    observables = serializers.ListField(child=serializers.DictField(), required=False, default=list)

    def validate_techniques(self, value):
        cleaned = []
        for item in value:
            technique_id = str(
                item.get("technique_id") or item.get("attack_id") or item.get("id") or ""
            ).strip()
            if not technique_id:
                raise serializers.ValidationError("Every technique needs a technique_id.")
            cleaned.append(
                {
                    "technique_id": technique_id.upper(),
                    "name": str(item.get("name") or ""),
                    "confidence": int(item.get("confidence") or 50),
                    "evidence_excerpt": str(item.get("evidence_excerpt") or ""),
                    "review_status": str(item.get("review_status") or "pending"),
                }
            )
        return cleaned

    def validate_vulnerabilities(self, value):
        cleaned = []
        for item in value:
            cve_id = str(item.get("cve_id") or item.get("id") or "").strip().upper()
            if not cve_id:
                raise serializers.ValidationError("Every vulnerability needs a cve_id.")
            cleaned.append(
                {
                    "cve_id": cve_id,
                    "evidence_excerpt": str(item.get("evidence_excerpt") or ""),
                }
            )
        return cleaned


class GapFindingSerializer(serializers.ModelSerializer):
    technique_id = serializers.CharField(source="technique.technique_id", read_only=True)
    cve_id = serializers.CharField(source="vulnerability.cve_id", read_only=True)

    class Meta:
        model = GapFinding
        fields = [
            "id",
            "category",
            "state",
            "priority",
            "title",
            "technique_id",
            "cve_id",
            "affected_asset_count",
            "critical_asset_count",
            "recommendation",
            "rationale",
            "evidence",
            "created_at",
            "updated_at",
        ]


class AssessmentSerializer(serializers.ModelSerializer):
    report_title = serializers.CharField(source="report.title", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)
    findings = GapFindingSerializer(many=True, read_only=True)

    class Meta:
        model = Assessment
        fields = [
            "id",
            "report",
            "report_title",
            "status",
            "started_at",
            "completed_at",
            "created_by_username",
            "summary",
            "error_summary",
            "findings",
            "created_at",
            "updated_at",
        ]
