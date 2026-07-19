from django import forms
from django.contrib import admin

from catalog.services.audit import record_security_event
from threatbridge.authorization import Permissions, is_allowed

from .models import ExternalObject, Integration, SyncRecordError, SyncRun
from .secrets import redacted_configuration


class IntegrationAdminForm(forms.ModelForm):
    secret_reference = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=(
            "Enter a secret lookup reference. The stored reference is never rendered; "
            "leave blank to retain it when editing."
        ),
    )

    class Meta:
        model = Integration
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial["configuration"] = redacted_configuration(
            self.initial.get("configuration", {})
        )

    def clean_secret_reference(self):
        value = self.cleaned_data.get("secret_reference", "").strip()
        if value or not self.instance.pk:
            return value
        return Integration.objects.only("secret_reference").get(
            pk=self.instance.pk
        ).secret_reference


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    form = IntegrationAdminForm
    exclude = ("cursor",)
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

    def has_view_permission(self, request, obj=None):
        return is_allowed(request.user, Permissions.VIEW_INTEGRATIONS)

    @staticmethod
    def _can_configure(request):
        return is_allowed(
            request.user,
            Permissions.VIEW_INTEGRATIONS,
        ) and is_allowed(request.user, Permissions.CONFIGURE_INTEGRATIONS)

    def has_add_permission(self, request):
        return self._can_configure(request)

    def has_change_permission(self, request, obj=None):
        return self._can_configure(request)

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        record_security_event(
            event_type="integration.configuration_changed",
            origin="admin:integration",
            outcome="succeeded",
            actor=request.user,
            target_type="integration",
            target_identifier=obj.pk,
            metadata={"operation": "updated" if change else "created"},
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
    exclude = ("cursor_before", "cursor_after")
    readonly_fields = [
        field.name
        for field in SyncRun._meta.fields
        if field.name not in {"cursor_before", "cursor_after"}
    ]
    inlines = [SyncRecordErrorInline]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_view_permission(self, request, obj=None):
        return is_allowed(request.user, Permissions.VIEW_INTEGRATIONS)


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
    fields = (
        "integration",
        "object_type",
        "external_id",
        "natural_key",
        "source_updated_at",
        "content_hash",
        "first_seen_at",
        "last_seen_at",
        "is_deleted",
        "deleted_at",
        "deleted_by",
        "deletion_reason",
        "deletion_origin",
        "restored_at",
        "restored_by",
        "restoration_reason",
        "restoration_origin",
        "projection_status",
        "projection_error",
        "projected_at",
    )
    readonly_fields = (
        "content_hash",
        "first_seen_at",
        "last_seen_at",
        "projection_status",
        "projection_error",
        "projected_at",
        "integration",
        "object_type",
        "external_id",
        "natural_key",
        "source_updated_at",
        "is_deleted",
        "deleted_at",
        "deleted_by",
        "deletion_reason",
        "deletion_origin",
        "restored_at",
        "restored_by",
        "restoration_reason",
        "restoration_origin",
    )

    def get_queryset(self, request):
        if is_allowed(
            request.user,
            Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE,
        ) and is_allowed(request.user, Permissions.VIEW_DELETED_SOURCE_EVIDENCE):
            return ExternalObject.all_objects.select_related("integration")
        return ExternalObject.objects.select_related("integration")

    def has_view_permission(self, request, obj=None):
        if obj is not None and obj.is_deleted:
            return is_allowed(
                request.user,
                Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE,
            ) and is_allowed(
                request.user,
                Permissions.VIEW_DELETED_SOURCE_EVIDENCE,
            )
        return is_allowed(request.user, Permissions.VIEW_RESTRICTED_SOURCE_EVIDENCE)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
