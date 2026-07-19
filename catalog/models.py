from __future__ import annotations

import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class TimestampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Criticality(models.TextChoices):
    UNKNOWN = "unknown", "Unknown"
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class Asset(TimestampedModel):
    canonical_key = models.CharField(max_length=600, unique=True)
    display_name = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255, blank=True)
    fqdn = models.CharField(max_length=500, blank=True)
    os_platform = models.CharField(max_length=150, blank=True)
    os_version = models.CharField(max_length=150, blank=True)
    environment = models.CharField(max_length=100, blank=True)
    business_service = models.CharField(max_length=255, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    criticality = models.CharField(
        max_length=16,
        choices=Criticality.choices,
        default=Criticality.UNKNOWN,
    )
    internet_exposed = models.BooleanField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["display_name", "id"]
        indexes = [
            models.Index(fields=["hostname"]),
            models.Index(fields=["fqdn"]),
            models.Index(fields=["criticality"]),
        ]

    def __str__(self) -> str:
        return self.display_name


class AssetAlias(TimestampedModel):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="aliases")
    namespace = models.CharField(max_length=150)
    kind = models.CharField(max_length=64)
    value = models.CharField(max_length=600)
    normalized_value = models.CharField(max_length=600)

    class Meta:
        ordering = ["namespace", "kind", "normalized_value"]
        constraints = [
            models.UniqueConstraint(
                fields=["namespace", "kind", "normalized_value"],
                name="catalog_unique_asset_alias",
            )
        ]
        indexes = [models.Index(fields=["kind", "normalized_value"])]

    def __str__(self) -> str:
        return f"{self.namespace}:{self.kind}:{self.value}"


class AssetSource(TimestampedModel):
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="asset_projection",
    )
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="sources")


class SoftwareProduct(TimestampedModel):
    vendor = models.CharField(max_length=255, blank=True)
    name = models.CharField(max_length=255)
    normalized_vendor = models.CharField(max_length=255)
    normalized_name = models.CharField(max_length=255)
    cpe = models.CharField(max_length=600, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["vendor", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["normalized_vendor", "normalized_name"],
                name="catalog_unique_software_product",
            )
        ]

    def __str__(self) -> str:
        return f"{self.vendor} {self.name}".strip()


class SoftwareInstallation(TimestampedModel):
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="software_installation_projection",
    )
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="software_installations",
    )
    product = models.ForeignKey(
        SoftwareProduct,
        on_delete=models.PROTECT,
        related_name="installations",
    )
    version = models.CharField(max_length=255, blank=True)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    end_of_support_status = models.CharField(max_length=100, blank=True)
    end_of_support_date = models.DateField(null=True, blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["asset__display_name", "product__name", "version"]
        indexes = [models.Index(fields=["version"])]


class Vulnerability(TimestampedModel):
    cve_id = models.CharField(max_length=32, unique=True)
    title = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=32, blank=True)
    cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    exploitability = models.CharField(max_length=100, blank=True)
    known_exploited = models.BooleanField(default=False)
    exploit_available = models.BooleanField(default=False)
    published_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["cve_id"]
        indexes = [models.Index(fields=["severity", "known_exploited"])]

    def __str__(self) -> str:
        return self.cve_id


class VulnerabilitySource(TimestampedModel):
    source_object = models.ForeignKey(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="vulnerability_projections",
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="sources",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source_object", "vulnerability"],
                name="catalog_unique_vulnerability_source",
            )
        ]


class VulnerabilityFinding(TimestampedModel):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        FIXED = "fixed", "Fixed"
        ACCEPTED = "accepted", "Accepted risk"
        FALSE_POSITIVE = "false_positive", "False positive"
        UNKNOWN = "unknown", "Unknown"

    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="vulnerability_finding_projection",
    )
    asset = models.ForeignKey(
        Asset,
        on_delete=models.CASCADE,
        related_name="vulnerability_findings",
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.PROTECT,
        related_name="findings",
    )
    product = models.ForeignKey(
        SoftwareProduct,
        on_delete=models.PROTECT,
        related_name="vulnerability_findings",
        null=True,
        blank=True,
    )
    installed_version = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=32, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    remediation = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-last_seen_at", "vulnerability__cve_id"]
        indexes = [
            models.Index(fields=["status", "severity"]),
            models.Index(fields=["asset", "status"]),
        ]


class AttackTechnique(TimestampedModel):
    technique_id = models.CharField(max_length=32, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    tactics = models.JSONField(default=list, blank=True)
    platforms = models.JSONField(default=list, blank=True)
    data_sources = models.JSONField(default=list, blank=True)
    revoked = models.BooleanField(default=False)
    deprecated = models.BooleanField(default=False)
    attack_version = models.CharField(max_length=64, blank=True)
    source_object = models.ForeignKey(
        "integrations.ExternalObject",
        on_delete=models.SET_NULL,
        related_name="attack_technique_projections",
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["technique_id"]

    def __str__(self) -> str:
        return f"{self.technique_id} - {self.name}"


class TelemetrySource(TimestampedModel):
    key = models.SlugField(max_length=180, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    available = models.BooleanField(null=True, blank=True)
    integration = models.ForeignKey(
        "integrations.Integration",
        on_delete=models.SET_NULL,
        related_name="telemetry_sources",
        null=True,
        blank=True,
    )
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.SET_NULL,
        related_name="telemetry_source_projection",
        null=True,
        blank=True,
    )
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class DetectionRule(TimestampedModel):
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="detection_rule_projection",
    )
    integration = models.ForeignKey(
        "integrations.Integration",
        on_delete=models.CASCADE,
        related_name="detection_rules",
    )
    external_id = models.CharField(max_length=500)
    name = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    query = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=32, blank=True)
    owner = models.CharField(max_length=255, blank=True)
    source_updated_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    techniques = models.ManyToManyField(
        AttackTechnique,
        through="DetectionRuleTechnique",
        related_name="detection_rules",
    )
    telemetry_sources = models.ManyToManyField(
        TelemetrySource,
        through="DetectionRuleTelemetry",
        related_name="detection_rules",
    )

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "external_id"],
                name="catalog_unique_detection_per_integration",
            )
        ]
        indexes = [models.Index(fields=["enabled", "severity"])]

    def __str__(self) -> str:
        return self.name


class DetectionRuleTechnique(models.Model):
    detection_rule = models.ForeignKey(DetectionRule, on_delete=models.CASCADE)
    technique = models.ForeignKey(AttackTechnique, on_delete=models.CASCADE)
    confidence = models.PositiveSmallIntegerField(default=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["detection_rule", "technique"],
                name="catalog_unique_detection_technique",
            )
        ]


class DetectionRuleTelemetry(models.Model):
    detection_rule = models.ForeignKey(DetectionRule, on_delete=models.CASCADE)
    telemetry_source = models.ForeignKey(TelemetrySource, on_delete=models.CASCADE)
    required = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["detection_rule", "telemetry_source"],
                name="catalog_unique_detection_telemetry",
            )
        ]


class ValidationTest(TimestampedModel):
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.SET_NULL,
        related_name="validation_test_projection",
        null=True,
        blank=True,
    )
    integration = models.ForeignKey(
        "integrations.Integration",
        on_delete=models.SET_NULL,
        related_name="validation_tests",
        null=True,
        blank=True,
    )
    external_id = models.CharField(max_length=500)
    name = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    procedure = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)
    techniques = models.ManyToManyField(AttackTechnique, related_name="validation_tests")

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "external_id"],
                name="catalog_unique_validation_test_per_integration",
            )
        ]

    def __str__(self) -> str:
        return self.name


class ValidationResult(TimestampedModel):
    class Outcome(models.TextChoices):
        PASSED = "passed", "Passed"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"
        ERROR = "error", "Error"
        NOT_RUN = "not_run", "Not run"

    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="validation_result_projection",
    )
    test = models.ForeignKey(ValidationTest, on_delete=models.CASCADE, related_name="results")
    technique = models.ForeignKey(
        AttackTechnique,
        on_delete=models.SET_NULL,
        related_name="validation_results",
        null=True,
        blank=True,
    )
    detection_rule = models.ForeignKey(
        DetectionRule,
        on_delete=models.SET_NULL,
        related_name="validation_results",
        null=True,
        blank=True,
    )
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    executed_at = models.DateTimeField(null=True, blank=True)
    summary = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-executed_at", "-created_at"]
        indexes = [models.Index(fields=["outcome", "executed_at"])]


class ThreatReport(TimestampedModel):
    source_object = models.OneToOneField(
        "integrations.ExternalObject",
        on_delete=models.CASCADE,
        related_name="threat_report_projection",
    )
    integration = models.ForeignKey(
        "integrations.Integration",
        on_delete=models.CASCADE,
        related_name="threat_reports",
    )
    external_id = models.CharField(max_length=500)
    title = models.CharField(max_length=700)
    summary = models.TextField(blank=True)
    source_name = models.CharField(max_length=255, blank=True)
    source_url = models.URLField(max_length=1000, blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    confidence = models.PositiveSmallIntegerField(default=50)
    tlp = models.CharField(max_length=32, blank=True)
    targeted_industries = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-published_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "external_id"],
                name="catalog_unique_threat_report_per_integration",
            )
        ]

    def __str__(self) -> str:
        return self.title


class ThreatReportTechnique(TimestampedModel):
    class ReviewStatus(models.TextChoices):
        APPROVED = "approved", "Approved"
        PENDING = "pending", "Pending"
        REJECTED = "rejected", "Rejected"
        UNCERTAIN = "uncertain", "Uncertain"

    report = models.ForeignKey(
        ThreatReport,
        on_delete=models.CASCADE,
        related_name="technique_links",
    )
    technique = models.ForeignKey(
        AttackTechnique,
        on_delete=models.CASCADE,
        related_name="threat_report_links",
    )
    confidence = models.PositiveSmallIntegerField(default=50)
    review_status = models.CharField(
        max_length=16,
        choices=ReviewStatus.choices,
        default=ReviewStatus.PENDING,
    )
    evidence_excerpt = models.TextField(blank=True)

    class Meta:
        permissions = [
            ("review_attack_mapping", "Can approve or reject ATT&CK mappings"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["report", "technique"],
                name="catalog_unique_report_technique",
            )
        ]


class ThreatReportVulnerability(TimestampedModel):
    report = models.ForeignKey(
        ThreatReport,
        on_delete=models.CASCADE,
        related_name="vulnerability_links",
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="threat_report_links",
    )
    evidence_excerpt = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["report", "vulnerability"],
                name="catalog_unique_report_vulnerability",
            )
        ]


class Observable(TimestampedModel):
    report = models.ForeignKey(ThreatReport, on_delete=models.CASCADE, related_name="observables")
    observable_type = models.CharField(max_length=64)
    value = models.CharField(max_length=2000)
    confidence = models.PositiveSmallIntegerField(default=50)
    first_seen_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["observable_type", "value"]
        constraints = [
            models.UniqueConstraint(
                fields=["report", "observable_type", "value"],
                name="catalog_unique_report_observable",
            )
        ]


class Assessment(TimestampedModel):
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report = models.ForeignKey(ThreatReport, on_delete=models.CASCADE, related_name="assessments")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="threatbridge_assessments",
        null=True,
        blank=True,
    )
    origin = models.CharField(max_length=255, default="unknown")
    evidence_sources = models.ManyToManyField(
        "integrations.ExternalObject",
        related_name="assessments",
        blank=True,
    )
    evidence_provenance_complete = models.BooleanField(default=False)
    summary = models.JSONField(default=dict, blank=True)
    error_summary = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]
        permissions = [
            ("run_assessment", "Can run or recalculate assessments"),
        ]


class GapFinding(TimestampedModel):
    class Category(models.TextChoices):
        TECHNIQUE = "technique", "Technique coverage"
        VULNERABILITY = "vulnerability", "Vulnerability exposure"

    class State(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        EXPOSURE_NOT_FOUND = "exposure_not_found", "Exposure not found"
        EXPOSURE_CONFIRMED = "exposure_confirmed", "Exposure confirmed"
        TELEMETRY_MISSING = "telemetry_missing", "Telemetry missing"
        DETECTION_MISSING = "detection_missing", "Detection missing"
        DETECTION_DOCUMENTED = "detection_documented", "Detection documented"
        VALIDATION_FAILED = "validation_failed", "Validation failed"
        PARTIALLY_VALIDATED = "partially_validated", "Partially validated"
        VALIDATED = "validated", "Validated"
        VALIDATED_WITH_LIMITATIONS = "validated_with_limitations", "Validated with limitations"

    class Priority(models.TextChoices):
        INFO = "info", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    assessment = models.ForeignKey(Assessment, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=24, choices=Category.choices)
    state = models.CharField(max_length=40, choices=State.choices)
    priority = models.CharField(max_length=16, choices=Priority.choices, default=Priority.MEDIUM)
    title = models.CharField(max_length=700)
    technique = models.ForeignKey(
        AttackTechnique,
        on_delete=models.SET_NULL,
        related_name="gap_findings",
        null=True,
        blank=True,
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        related_name="gap_findings",
        null=True,
        blank=True,
    )
    affected_asset_count = models.PositiveIntegerField(default=0)
    critical_asset_count = models.PositiveIntegerField(default=0)
    recommendation = models.TextField(blank=True)
    rationale = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["priority", "category", "title"]
        indexes = [
            models.Index(fields=["state", "priority"]),
            models.Index(fields=["assessment", "category"]),
        ]


class AppendOnlyModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Append-only records cannot be modified.")
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Append-only records cannot be deleted.")


class AttackMappingReviewEvent(AppendOnlyModel):
    mapping = models.ForeignKey(
        ThreatReportTechnique,
        on_delete=models.SET_NULL,
        related_name="review_events",
        null=True,
        blank=True,
    )
    mapping_identifier = models.CharField(max_length=64)
    previous_state = models.CharField(max_length=16, choices=ThreatReportTechnique.ReviewStatus)
    new_state = models.CharField(max_length=16, choices=ThreatReportTechnique.ReviewStatus)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="threatbridge_mapping_reviews",
        null=True,
        blank=True,
    )
    actor_label = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)
    origin = models.CharField(max_length=255)

    class Meta:
        ordering = ["-timestamp", "-id"]


class SecurityAuditEvent(AppendOnlyModel):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="threatbridge_security_events",
        null=True,
        blank=True,
    )
    actor_label = models.CharField(max_length=255, blank=True)
    origin = models.CharField(max_length=255)
    event_type = models.CharField(max_length=100)
    target_type = models.CharField(max_length=100, blank=True)
    target_identifier = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    outcome = models.CharField(max_length=32)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp", "-id"]
        permissions = [
            (
                "administer_security_configuration",
                "Can administer ThreatBridge security configuration",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.event_type}: {self.outcome}"
