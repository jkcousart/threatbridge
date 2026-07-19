from django.contrib import admin

from .models import ExternalObject, Integration, SyncRecordError, SyncRun


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "kind",
        "enabled",
        "health",
        "adapter_path",
        "last_success_at",
    )
    list_filter = ("kind", "enabled", "health")
    search_fields = ("name", "slug", "adapter_path")
    readonly_fields = (
        "cursor",
        "health",
        "last_tested_at",
        "last_test_result",
        "last_attempt_at",
        "last_success_at",
        "last_error",
        "created_at",
        "updated_at",
    )


class SyncRecordErrorInline(admin.TabularInline):
    model = SyncRecordError
    extra = 0
    readonly_fields = (
        "stage",
        "object_type",
        "external_id",
        "error_type",
        "error_message",
        "raw_summary",
        "created_at",
    )
    can_delete = False


@admin.register(SyncRun)
class SyncRunAdmin(admin.ModelAdmin):
    list_display = (
        "integration",
        "status",
        "started_at",
        "finished_at",
        "batches_processed",
        "records_received",
        "records_accepted",
        "records_rejected",
        "records_projected",
    )
    list_filter = ("status", "integration")
    readonly_fields = [field.name for field in SyncRun._meta.fields]
    inlines = [SyncRecordErrorInline]


@admin.register(ExternalObject)
class ExternalObjectAdmin(admin.ModelAdmin):
    list_display = (
        "integration",
        "object_type",
        "external_id",
        "source_updated_at",
        "projection_status",
        "projected_at",
        "is_deleted",
    )
    list_filter = ("integration", "object_type", "projection_status", "is_deleted")
    search_fields = ("external_id", "natural_key")
    readonly_fields = (
        "content_hash",
        "first_seen_at",
        "last_seen_at",
        "projection_status",
        "projection_error",
        "projected_at",
    )
