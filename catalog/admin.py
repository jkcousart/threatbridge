from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin as DjangoGroupAdmin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.models import Group, User

from threatbridge.authorization import Permissions, is_allowed

from .models import (
    Assessment,
    Asset,
    AssetAlias,
    AssetSource,
    AttackMappingReviewEvent,
    AttackTechnique,
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleTelemetry,
    GapFinding,
    Observable,
    SecurityAuditEvent,
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
    VulnerabilitySource,
)
from .provenance import active_admin_queryset
from .services.audit import record_security_event


class ProvenanceReadOnlyAdmin(admin.ModelAdmin):
    """Permit inspection without direct mutation of provenance-derived records."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def get_queryset(self, request):
        return active_admin_queryset(self.model, super().get_queryset(request))


class SecurityConfigurationAdminMixin:
    """Protect identity and permission assignment with the application policy."""

    @staticmethod
    def _is_security_administrator(request):
        return is_allowed(request.user, Permissions.ADMINISTER_SECURITY_CONFIGURATION)

    def has_module_permission(self, request):
        return self._is_security_administrator(request)

    def has_view_permission(self, request, obj=None):
        return self._is_security_administrator(request)

    def has_add_permission(self, request):
        return self._is_security_administrator(request)

    def has_change_permission(self, request, obj=None):
        return self._is_security_administrator(request)

    def has_delete_permission(self, request, obj=None):
        return self._is_security_administrator(request)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        record_security_event(
            event_type="security_configuration.changed",
            origin=f"admin:{self.model._meta.label_lower}",
            outcome="succeeded",
            actor=request.user,
            target_type=self.model._meta.label_lower,
            target_identifier=form.instance.pk,
            metadata={"operation": "updated" if change else "created"},
        )

    def delete_model(self, request, obj):
        record_security_event(
            event_type="security_configuration.changed",
            origin=f"admin:{self.model._meta.label_lower}",
            outcome="succeeded",
            actor=request.user,
            target_type=self.model._meta.label_lower,
            target_identifier=obj.pk,
            metadata={"operation": "deleted"},
        )
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset):
        identifiers = list(queryset.values_list("pk", flat=True)[:100])
        record_security_event(
            event_type="security_configuration.changed",
            origin=f"admin:{self.model._meta.label_lower}",
            outcome="succeeded",
            actor=request.user,
            target_type=self.model._meta.label_lower,
            metadata={
                "operation": "bulk_deleted",
                "target_identifiers": identifiers,
                "truncated": queryset.count() > len(identifiers),
            },
        )
        super().delete_queryset(request, queryset)


admin.site.unregister(User)
admin.site.unregister(Group)


@admin.register(User)
class PolicyUserAdmin(SecurityConfigurationAdminMixin, DjangoUserAdmin):
    pass


@admin.register(Group)
class PolicyGroupAdmin(SecurityConfigurationAdminMixin, DjangoGroupAdmin):
    pass


@admin.register(Asset)
class AssetAdmin(ProvenanceReadOnlyAdmin):
    list_display = (
        "display_name",
        "hostname",
        "business_service",
        "criticality",
        "internet_exposed",
        "last_seen_at",
    )
    list_filter = ("criticality", "internet_exposed", "environment")
    search_fields = ("display_name", "hostname", "fqdn", "business_service", "owner")


@admin.register(SoftwareProduct)
class SoftwareProductAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("vendor", "name", "cpe")
    search_fields = ("vendor", "name", "cpe")


@admin.register(SoftwareInstallation)
class SoftwareInstallationAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("asset", "product", "version", "last_seen_at")
    list_filter = ("product__vendor",)
    search_fields = ("asset__display_name", "product__name", "version")
    raw_id_fields = ("source_object", "asset", "product")


@admin.register(Vulnerability)
class VulnerabilityAdmin(ProvenanceReadOnlyAdmin):
    list_display = (
        "cve_id",
        "severity",
        "cvss_score",
        "known_exploited",
        "exploit_available",
    )
    list_filter = ("severity", "known_exploited", "exploit_available")
    search_fields = ("cve_id", "title", "description")


@admin.register(VulnerabilityFinding)
class VulnerabilityFindingAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("vulnerability", "asset", "severity", "status", "last_seen_at")
    list_filter = ("status", "severity")
    search_fields = ("vulnerability__cve_id", "asset__display_name", "installed_version")
    raw_id_fields = ("source_object", "asset", "vulnerability", "product")


@admin.register(AttackTechnique)
class AttackTechniqueAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("technique_id", "name", "revoked", "deprecated", "attack_version")
    list_filter = ("revoked", "deprecated")
    search_fields = ("technique_id", "name", "description")


@admin.register(DetectionRule)
class DetectionRuleAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("name", "integration", "external_id", "enabled", "severity", "owner")
    list_filter = ("enabled", "severity", "integration")
    search_fields = ("name", "external_id", "description", "query", "owner")
    raw_id_fields = ("source_object",)


@admin.register(TelemetrySource)
class TelemetrySourceAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("name", "key", "available", "integration")
    list_filter = ("available", "integration")
    search_fields = ("name", "key", "description")


class ThreatReportTechniqueInline(admin.TabularInline):
    model = ThreatReportTechnique
    extra = 0
    can_delete = False
    readonly_fields = (
        "technique",
        "confidence",
        "review_status",
        "evidence_excerpt",
        "created_at",
        "updated_at",
    )

    def has_add_permission(self, request, obj=None):
        return False


class ThreatReportVulnerabilityInline(admin.TabularInline):
    model = ThreatReportVulnerability
    extra = 0
    can_delete = False
    readonly_fields = ("vulnerability", "evidence_excerpt", "created_at", "updated_at")

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ThreatReport)
class ThreatReportAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("title", "source_name", "published_at", "confidence", "tlp", "integration")
    list_filter = ("integration", "tlp")
    search_fields = ("title", "summary", "source_name", "external_id")
    raw_id_fields = ("source_object",)
    inlines = (ThreatReportTechniqueInline, ThreatReportVulnerabilityInline)


@admin.register(Assessment)
class AssessmentAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("id", "report", "status", "created_by", "started_at", "completed_at")
    list_filter = ("status",)
    search_fields = ("id", "report__title")


@admin.register(GapFinding)
class GapFindingAdmin(ProvenanceReadOnlyAdmin):
    list_display = ("title", "assessment", "category", "state", "priority")
    list_filter = ("category", "state", "priority")
    search_fields = ("title", "recommendation", "rationale")


@admin.register(AttackMappingReviewEvent)
class AttackMappingReviewEventAdmin(ProvenanceReadOnlyAdmin):
    list_display = (
        "mapping_identifier",
        "previous_state",
        "new_state",
        "actor_label",
        "origin",
        "timestamp",
    )
    search_fields = ("mapping_identifier", "actor_label", "origin")

    def has_view_permission(self, request, obj=None):
        return is_allowed(request.user, Permissions.REVIEW_ATTACK_MAPPINGS)


@admin.register(SecurityAuditEvent)
class SecurityAuditEventAdmin(ProvenanceReadOnlyAdmin):
    list_display = (
        "event_type",
        "outcome",
        "actor_label",
        "origin",
        "target_type",
        "target_identifier",
        "timestamp",
    )
    list_filter = ("event_type", "outcome", "origin")
    search_fields = (
        "event_type",
        "actor_label",
        "target_type",
        "target_identifier",
    )

    def has_view_permission(self, request, obj=None):
        return is_allowed(request.user, Permissions.VIEW_SECURITY_AUDIT_EVENTS)


for model in (
    AssetAlias,
    AssetSource,
    DetectionRuleTechnique,
    DetectionRuleTelemetry,
    ValidationTest,
    ValidationResult,
    Observable,
    VulnerabilitySource,
):
    admin.site.register(model, ProvenanceReadOnlyAdmin)
