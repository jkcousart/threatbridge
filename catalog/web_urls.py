from django.urls import path

from . import web_views

urlpatterns = [
    path("", web_views.dashboard, name="dashboard"),
    path("integrations/", web_views.integration_list, name="web-integration-list"),
    path("imports/new/", web_views.file_import_new, name="web-file-import-new"),
    path(
        "imports/preview/",
        web_views.file_import_preview,
        name="web-file-import-preview",
    ),
    path(
        "integrations/<int:pk>/test/",
        web_views.integration_test,
        name="web-integration-test",
    ),
    path(
        "integrations/<int:pk>/sync/",
        web_views.integration_sync,
        name="web-integration-sync",
    ),
    path("evidence/", web_views.source_evidence_list, name="web-source-evidence-list"),
    path("reports/", web_views.threat_report_list, name="web-threat-report-list"),
    path(
        "reports/<int:pk>/",
        web_views.threat_report_detail,
        name="web-threat-report-detail",
    ),
    path(
        "report-techniques/<int:pk>/review/",
        web_views.review_technique,
        name="web-review-technique",
    ),
    path("reports/<int:pk>/assess/", web_views.assess_report, name="web-assess-report"),
    path(
        "assessments/<uuid:pk>/",
        web_views.assessment_detail,
        name="web-assessment-detail",
    ),
]
