from django.contrib import admin

from .models import (
    Assessment,
    Asset,
    AssetAlias,
    AssetSource,
    AttackTechnique,
    DetectionRule,
    DetectionRuleTechnique,
    DetectionRuleTelemetry,
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


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
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
class SoftwareProductAdmin(admin.ModelAdmin):
    list_display = ("vendor", "name", "cpe")
    search_fields = ("vendor", "name", "cpe")


@admin.register(SoftwareInstallation)
class SoftwareInstallationAdmin(admin.ModelAdmin):
    list_display = ("asset", "product", "version", "last_seen_at")
    list_filter = ("product__vendor",)
    search_fields = ("asset__display_name", "product__name", "version")
    raw_id_fields = ("source_object", "asset", "product")


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
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
class VulnerabilityFindingAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "asset", "severity", "status", "last_seen_at")
    list_filter = ("status", "severity")
    search_fields = ("vulnerability__cve_id", "asset__display_name", "installed_version")
    raw_id_fields = ("source_object", "asset", "vulnerability", "product")


@admin.register(AttackTechnique)
class AttackTechniqueAdmin(admin.ModelAdmin):
    list_display = ("technique_id", "name", "revoked", "deprecated", "attack_version")
    list_filter = ("revoked", "deprecated")
    search_fields = ("technique_id", "name", "description")


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "integration", "external_id", "enabled", "severity", "owner")
    list_filter = ("enabled", "severity", "integration")
    search_fields = ("name", "external_id", "description", "query", "owner")
    raw_id_fields = ("source_object",)


@admin.register(TelemetrySource)
class TelemetrySourceAdmin(admin.ModelAdmin):
    list_display = ("name", "key", "available", "integration")
    list_filter = ("available", "integration")
    search_fields = ("name", "key", "description")


class ThreatReportTechniqueInline(admin.TabularInline):
    model = ThreatReportTechnique
    extra = 0


class ThreatReportVulnerabilityInline(admin.TabularInline):
    model = ThreatReportVulnerability
    extra = 0


@admin.register(ThreatReport)
class ThreatReportAdmin(admin.ModelAdmin):
    list_display = ("title", "source_name", "published_at", "confidence", "tlp", "integration")
    list_filter = ("integration", "tlp")
    search_fields = ("title", "summary", "source_name", "external_id")
    raw_id_fields = ("source_object",)
    inlines = (ThreatReportTechniqueInline, ThreatReportVulnerabilityInline)


@admin.register(Assessment)
class AssessmentAdmin(admin.ModelAdmin):
    list_display = ("id", "report", "status", "created_by", "started_at", "completed_at")
    list_filter = ("status",)
    search_fields = ("id", "report__title")


@admin.register(GapFinding)
class GapFindingAdmin(admin.ModelAdmin):
    list_display = ("title", "assessment", "category", "state", "priority")
    list_filter = ("category", "state", "priority")
    search_fields = ("title", "recommendation", "rationale")


admin.site.register(AssetAlias)
admin.site.register(AssetSource)
admin.site.register(DetectionRuleTechnique)
admin.site.register(DetectionRuleTelemetry)
admin.site.register(ValidationTest)
admin.site.register(ValidationResult)
admin.site.register(Observable)
