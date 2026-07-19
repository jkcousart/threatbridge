from django.db import models


class Integration(models.Model):
    class Kind(models.TextChoices):
        THREAT_INTELLIGENCE = "threat_intelligence", "Threat intelligence"
        VULNERABILITY = "vulnerability", "Vulnerability management"
        ASSET = "asset", "Asset inventory"
        DETECTION = "detection", "Detection platform"
        VALIDATION = "validation", "Security validation"
        GENERIC = "generic", "Generic"

    class Health(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        HEALTHY = "healthy", "Healthy"
        DEGRADED = "degraded", "Degraded"
        ERROR = "error", "Error"

    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.GENERIC)
    adapter_path = models.CharField(
        max_length=255,
        help_text="Dotted Python path to the adapter class.",
    )
    enabled = models.BooleanField(default=True)
    configuration = models.JSONField(default=dict, blank=True)
    secret_reference = models.CharField(
        max_length=255,
        blank=True,
        help_text="Reference to an external secret; never store credentials here.",
    )
    cursor = models.JSONField(default=dict, blank=True)
    health = models.CharField(max_length=16, choices=Health.choices, default=Health.UNKNOWN)
    last_tested_at = models.DateTimeField(null=True, blank=True)
    last_test_result = models.JSONField(default=dict, blank=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class SyncRun(models.Model):
    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    integration = models.ForeignKey(Integration, on_delete=models.CASCADE, related_name="sync_runs")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    cursor_before = models.JSONField(default=dict, blank=True)
    cursor_after = models.JSONField(default=dict, blank=True)
    batches_processed = models.PositiveIntegerField(default=0)
    records_received = models.PositiveIntegerField(default=0)
    records_accepted = models.PositiveIntegerField(default=0)
    records_rejected = models.PositiveIntegerField(default=0)
    records_created = models.PositiveIntegerField(default=0)
    records_updated = models.PositiveIntegerField(default=0)
    records_unchanged = models.PositiveIntegerField(default=0)
    records_projected = models.PositiveIntegerField(default=0)
    projection_failures = models.PositiveIntegerField(default=0)
    error_summary = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at"]


class ExternalObject(models.Model):
    class ProjectionStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        PROJECTED = "projected", "Projected"
        SKIPPED = "skipped", "Skipped"
        FAILED = "failed", "Failed"

    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="external_objects",
    )
    object_type = models.CharField(max_length=100)
    external_id = models.CharField(max_length=500)
    natural_key = models.CharField(max_length=500, blank=True)
    source_updated_at = models.DateTimeField(null=True, blank=True)
    raw = models.JSONField(default=dict)
    normalized = models.JSONField(default=dict)
    content_hash = models.CharField(max_length=64)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    projection_status = models.CharField(
        max_length=16,
        choices=ProjectionStatus.choices,
        default=ProjectionStatus.PENDING,
    )
    projection_error = models.TextField(blank=True)
    projected_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "object_type", "external_id"],
                name="unique_external_object_per_integration_and_type",
            )
        ]
        indexes = [
            models.Index(fields=["object_type", "natural_key"]),
            models.Index(fields=["integration", "source_updated_at"]),
            models.Index(fields=["projection_status", "object_type"]),
        ]

    def __str__(self) -> str:
        return f"{self.integration.slug}:{self.object_type}:{self.external_id}"


class SyncRecordError(models.Model):
    class Stage(models.TextChoices):
        NORMALIZE = "normalize", "Normalize"
        STORE = "store", "Store"
        PROJECT = "project", "Project"

    sync_run = models.ForeignKey(SyncRun, on_delete=models.CASCADE, related_name="record_errors")
    stage = models.CharField(max_length=16, choices=Stage.choices)
    object_type = models.CharField(max_length=100, blank=True)
    external_id = models.CharField(max_length=500, blank=True)
    error_type = models.CharField(max_length=255)
    error_message = models.TextField()
    raw_summary = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
