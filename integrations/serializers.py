from __future__ import annotations

from rest_framework import serializers

from .import_schemas import IMPORT_OBJECT_TYPE_CHOICES
from .models import ExternalObject, Integration, SyncRecordError, SyncRun
from .registry import load_adapter


class IntegrationSerializer(serializers.ModelSerializer):
    secret_configured = serializers.SerializerMethodField()

    class Meta:
        model = Integration
        fields = [
            "id",
            "name",
            "slug",
            "kind",
            "adapter_path",
            "enabled",
            "configuration",
            "secret_reference",
            "secret_configured",
            "cursor",
            "health",
            "last_tested_at",
            "last_test_result",
            "last_attempt_at",
            "last_success_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "cursor",
            "health",
            "last_tested_at",
            "last_test_result",
            "last_attempt_at",
            "last_success_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        extra_kwargs = {"secret_reference": {"write_only": True, "required": False}}

    def get_secret_configured(self, obj: Integration) -> bool:
        return bool(obj.secret_reference)

    def validate_adapter_path(self, value: str) -> str:
        try:
            load_adapter(value)
        except (ImportError, TypeError, ValueError) as exc:
            raise serializers.ValidationError(str(exc)) from exc
        return value

    def validate_configuration(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Configuration must be a JSON object.")
        return value


class SyncRecordErrorSerializer(serializers.ModelSerializer):
    class Meta:
        model = SyncRecordError
        fields = [
            "id",
            "stage",
            "object_type",
            "external_id",
            "error_type",
            "error_message",
            "raw_summary",
            "created_at",
        ]


class SyncRunSerializer(serializers.ModelSerializer):
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)
    record_errors = SyncRecordErrorSerializer(many=True, read_only=True)

    class Meta:
        model = SyncRun
        fields = [
            "id",
            "integration",
            "integration_slug",
            "status",
            "started_at",
            "finished_at",
            "cursor_before",
            "cursor_after",
            "batches_processed",
            "records_received",
            "records_accepted",
            "records_rejected",
            "records_created",
            "records_updated",
            "records_unchanged",
            "records_projected",
            "projection_failures",
            "error_summary",
            "metadata",
            "record_errors",
        ]


class ExternalObjectSerializer(serializers.ModelSerializer):
    integration_slug = serializers.CharField(source="integration.slug", read_only=True)

    class Meta:
        model = ExternalObject
        fields = [
            "id",
            "integration_slug",
            "object_type",
            "external_id",
            "natural_key",
            "source_updated_at",
            "normalized",
            "content_hash",
            "first_seen_at",
            "last_seen_at",
            "is_deleted",
            "projection_status",
            "projection_error",
            "projected_at",
        ]


class FileImportSerializer(serializers.Serializer):
    file = serializers.FileField()
    integration_id = serializers.IntegerField(required=False, allow_null=True)
    name = serializers.CharField(required=False, allow_blank=True, max_length=200)
    object_type = serializers.ChoiceField(
        choices=[choice for choice, _label in IMPORT_OBJECT_TYPE_CHOICES],
        required=False,
        default="auto",
    )
    id_fields = serializers.CharField(required=False, allow_blank=True)
    records_key = serializers.CharField(required=False, allow_blank=True)
    natural_key_field = serializers.CharField(required=False, allow_blank=True)
    updated_at_field = serializers.CharField(required=False, allow_blank=True)
    delimiter = serializers.CharField(required=False, allow_blank=True, max_length=2)
    field_map = serializers.JSONField(required=False, default=dict)
    default_review_status = serializers.ChoiceField(
        choices=["pending", "approved", "uncertain"],
        required=False,
        default="pending",
    )
    strict_records = serializers.BooleanField(required=False, default=False)
    sync_now = serializers.BooleanField(required=False, default=True)

    def validate_integration_id(self, value):
        if value is None:
            return value
        if not Integration.objects.filter(pk=value).exists():
            raise serializers.ValidationError("Integration profile does not exist.")
        return value

    def validate_field_map(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Field map must be a JSON object.")
        return {str(key): str(destination) for key, destination in value.items()}


class FilePreviewSerializer(serializers.Serializer):
    file = serializers.FileField()
    object_type = serializers.CharField(required=False, allow_blank=True, default="auto")
    records_key = serializers.CharField(required=False, allow_blank=True)
    delimiter = serializers.CharField(required=False, allow_blank=True, max_length=2)
