from rest_framework.routers import DefaultRouter

from .views import (
    AssessmentViewSet,
    AssetViewSet,
    AttackTechniqueViewSet,
    DetectionRuleViewSet,
    SecurityAuditEventViewSet,
    SoftwareInstallationViewSet,
    SoftwareProductViewSet,
    TelemetrySourceViewSet,
    ThreatReportTechniqueViewSet,
    ThreatReportViewSet,
    ValidationResultViewSet,
    ValidationTestViewSet,
    VulnerabilityFindingViewSet,
    VulnerabilityViewSet,
)

router = DefaultRouter()
router.register("assets", AssetViewSet, basename="asset")
router.register("software-products", SoftwareProductViewSet, basename="software-product")
router.register(
    "software-installations",
    SoftwareInstallationViewSet,
    basename="software-installation",
)
router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register(
    "vulnerability-findings",
    VulnerabilityFindingViewSet,
    basename="vulnerability-finding",
)
router.register("attack-techniques", AttackTechniqueViewSet, basename="attack-technique")
router.register("telemetry-sources", TelemetrySourceViewSet, basename="telemetry-source")
router.register("detection-rules", DetectionRuleViewSet, basename="detection-rule")
router.register("validation-tests", ValidationTestViewSet, basename="validation-test")
router.register("validation-results", ValidationResultViewSet, basename="validation-result")
router.register("threat-reports", ThreatReportViewSet, basename="threat-report")
router.register(
    "threat-report-techniques",
    ThreatReportTechniqueViewSet,
    basename="threat-report-technique",
)
router.register("assessments", AssessmentViewSet, basename="assessment")
router.register(
    "security-audit-events",
    SecurityAuditEventViewSet,
    basename="security-audit-event",
)

urlpatterns = router.urls
