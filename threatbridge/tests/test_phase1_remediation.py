from __future__ import annotations

import hashlib
import warnings
from types import SimpleNamespace

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.paginator import UnorderedObjectListWarning
from django.db import transaction
from django.test import Client, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from catalog.models import (
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
    SoftwareInstallation,
    SoftwareProduct,
    TelemetrySource,
    ThreatReport,
    ThreatReportTechnique,
    ValidationResult,
    ValidationTest,
    Vulnerability,
    VulnerabilityFinding,
    VulnerabilitySource,
)
from catalog.provenance import attach_active_assessment_provenance
from catalog.services.assess import generate_assessment
from catalog.services.review import transition_attack_mapping_review
from integrations.admin import IntegrationAdmin
from integrations.models import ExternalObject, Integration
from integrations.services import project_external_object


def grant(user, app_label: str, codename: str) -> None:
    user.user_permissions.add(
        Permission.objects.get(
            content_type__app_label=app_label,
            codename=codename,
        )
    )


def source_object(
    integration: Integration,
    external_id: str,
    object_type: str,
    *,
    deleted: bool = False,
    normalized: dict | None = None,
) -> ExternalObject:
    return ExternalObject.all_objects.create(
        integration=integration,
        external_id=external_id,
        object_type=object_type,
        raw={"external_id": external_id},
        normalized=normalized or {"external_id": external_id},
        content_hash=hashlib.sha256(external_id.encode()).hexdigest(),
        is_deleted=deleted,
    )


class IntegrationLifecycleRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user_model = get_user_model()
        cls.configure_only = user_model.objects.create_user("configure-only")
        grant(cls.configure_only, "integrations", "configure_integration")

        cls.operator = user_model.objects.create_user("configuration-operator")
        grant(cls.operator, "integrations", "view_integration")
        grant(cls.operator, "integrations", "configure_integration")

        cls.superuser = user_model.objects.create_superuser(
            "integration-superuser",
            email="integration-superuser@example.invalid",
        )
        cls.integration = Integration.objects.create(
            name="Protected integration",
            slug="protected-integration",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )

    @staticmethod
    def api_for(user):
        client = APIClient()
        client.force_authenticate(user)
        return client

    def test_rest_integration_deletion_is_disabled_and_disable_remains_supported(self):
        api = self.api_for(self.superuser)

        response = api.delete(f"/api/integrations/{self.integration.pk}/")

        self.assertEqual(response.status_code, 405)
        self.assertTrue(Integration.objects.filter(pk=self.integration.pk).exists())

        response = api.patch(
            f"/api/integrations/{self.integration.pk}/",
            {"enabled": False},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.integration.refresh_from_db()
        self.assertFalse(self.integration.enabled)

    def test_admin_integration_deletion_is_disabled(self):
        model_admin = IntegrationAdmin(Integration, admin.site)
        request = SimpleNamespace(user=self.superuser, GET={})
        self.assertFalse(model_admin.has_delete_permission(request, self.integration))
        self.assertNotIn("delete_selected", model_admin.get_actions(request))

        client = Client()
        client.force_login(self.superuser)
        response = client.post(
            reverse(
                "admin:integrations_integration_delete",
                args=[self.integration.pk],
            ),
            {"post": "yes"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Integration.objects.filter(pk=self.integration.pk).exists())

    def test_rest_creation_requires_view_and_configure_permissions(self):
        payload = {
            "name": "Created integration",
            "slug": "created-integration",
            "adapter_path": "integrations.adapters.demo.DemoAdapter",
            "configuration": {},
        }
        denied = self.api_for(self.configure_only).post(
            "/api/integrations/",
            payload,
            format="json",
        )
        self.assertEqual(denied.status_code, 403)
        self.assertFalse(Integration.objects.filter(slug="created-integration").exists())

        allowed = self.api_for(self.operator).post(
            "/api/integrations/",
            payload,
            format="json",
        )
        self.assertEqual(allowed.status_code, 201)
        self.assertTrue(Integration.objects.filter(slug="created-integration").exists())


class StaleBoundaryRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = get_user_model().objects.create_superuser(
            "boundary-superuser",
            email="boundary-superuser@example.invalid",
        )
        cls.integration = Integration.objects.create(
            name="Boundary source",
            slug="boundary-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )

    def test_projection_reloads_and_rejects_a_stale_deleted_source(self):
        stale = source_object(
            self.integration,
            "stale-deleted-asset",
            "asset",
            normalized={
                "asset_external_id": "stale-deleted-asset",
                "hostname": "stale.example.invalid",
            },
        )
        ExternalObject.all_objects.filter(pk=stale.pk).update(is_deleted=True)

        with self.assertRaisesRegex(ValueError, "Deleted source evidence"):
            project_external_object(
                stale,
                actor=self.superuser,
                origin="test:stale_projection",
            )
        self.assertFalse(AssetSource.objects.filter(source_object_id=stale.pk).exists())

    def test_projection_uses_the_atomically_refreshed_source(self):
        stale = source_object(
            self.integration,
            "stale-content-asset",
            "asset",
            normalized={
                "asset_external_id": "stale-content-asset",
                "hostname": "old.example.invalid",
            },
        )
        ExternalObject.all_objects.filter(pk=stale.pk).update(
            normalized={
                "asset_external_id": "stale-content-asset",
                "hostname": "refreshed.example.invalid",
            }
        )

        _status, projected = project_external_object(
            stale,
            actor=self.superuser,
            origin="test:refreshed_projection",
        )

        self.assertEqual(projected.hostname, "refreshed.example.invalid")

    def test_assessment_reloads_and_rejects_a_stale_deleted_report_source(self):
        report_source = source_object(
            self.integration,
            "stale-report",
            "threat_report",
        )
        stale_report = ThreatReport.objects.create(
            source_object=report_source,
            integration=self.integration,
            external_id="stale-report",
            title="Stale assessment report",
        )
        stale_report = ThreatReport.objects.select_related("source_object").get(
            pk=stale_report.pk
        )
        ExternalObject.all_objects.filter(pk=report_source.pk).update(is_deleted=True)

        with self.assertRaisesRegex(ValueError, "Deleted source evidence"):
            generate_assessment(
                stale_report,
                actor=self.superuser,
                origin="test:stale_assessment",
            )
        self.assertFalse(Assessment.objects.filter(report=stale_report).exists())


class EvidenceDeletionLookupRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.auditor = get_user_model().objects.create_user("delete-auditor")
        grant(cls.auditor, "integrations", "view_restricted_source_evidence")
        grant(cls.auditor, "integrations", "view_deleted_source_evidence")
        grant(cls.auditor, "integrations", "delete_source_evidence")
        cls.integration = Integration.objects.create(
            name="Deletion source",
            slug="deletion-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )
        cls.evidence = source_object(
            cls.integration,
            "deletion-target",
            "asset",
        )
        cls.deleted_evidence = source_object(
            cls.integration,
            "deleted-list-target",
            "asset",
            deleted=True,
        )
        cls.later_evidence = source_object(
            cls.integration,
            "later-list-target",
            "asset",
        )

    def _listed_ids(self, path):
        api = APIClient()
        api.force_authenticate(self.auditor)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            response = api.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            any(
                issubclass(warning.category, UnorderedObjectListWarning)
                for warning in caught
            )
        )
        return [item["id"] for item in response.json()["results"]]

    def test_normal_evidence_list_has_stable_id_ordering(self):
        self.assertEqual(
            self._listed_ids("/api/external-objects/"),
            sorted((self.evidence.pk, self.later_evidence.pk)),
        )

    def test_include_deleted_evidence_list_has_stable_id_ordering(self):
        self.assertEqual(
            self._listed_ids("/api/external-objects/?include_deleted=true"),
            sorted(
                (
                    self.evidence.pk,
                    self.deleted_evidence.pk,
                    self.later_evidence.pk,
                )
            ),
        )

    def test_deleted_and_nonexistent_evidence_ids_are_indistinguishable(self):
        api = APIClient()
        api.force_authenticate(self.auditor)
        first = api.post(
            f"/api/external-objects/{self.evidence.pk}/delete-evidence/",
            {"reason": "Confirmed duplicate evidence"},
            format="json",
        )
        self.assertEqual(first.status_code, 200)

        already_deleted = api.post(
            f"/api/external-objects/{self.evidence.pk}/delete-evidence/",
            {"reason": "Second deletion attempt"},
            format="json",
        )
        nonexistent = api.post(
            "/api/external-objects/999999/delete-evidence/",
            {"reason": "Unknown evidence"},
            format="json",
        )

        self.assertEqual(already_deleted.status_code, 404)
        self.assertEqual(nonexistent.status_code, 404)
        self.assertEqual(already_deleted.json(), nonexistent.json())


class DeletedProvenanceRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user_model = get_user_model()
        cls.reader = user_model.objects.create_user("provenance-reader")
        cls.assessor = user_model.objects.create_user("provenance-assessor")
        grant(cls.assessor, "catalog", "run_assessment")
        cls.integration = Integration.objects.create(
            name="Provenance source",
            slug="provenance-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )

    @staticmethod
    def api_for(user):
        client = APIClient()
        client.force_authenticate(user)
        return client

    def test_rest_aggregates_exclude_deleted_provenance(self):
        asset_source = source_object(self.integration, "aggregate-asset", "asset")
        asset = Asset.objects.create(
            canonical_key="aggregate-asset",
            display_name="Aggregate asset",
        )
        AssetSource.objects.create(source_object=asset_source, asset=asset)

        product = SoftwareProduct.objects.create(
            vendor="Example",
            name="Agent",
            normalized_vendor="example",
            normalized_name="agent",
        )
        deleted_installation_source = source_object(
            self.integration,
            "deleted-installation",
            "software_installation",
            deleted=True,
        )
        SoftwareInstallation.objects.create(
            source_object=deleted_installation_source,
            asset=asset,
            product=product,
        )

        vulnerability_source = source_object(
            self.integration,
            "aggregate-vulnerability",
            "vulnerability",
        )
        vulnerability = Vulnerability.objects.create(cve_id="CVE-2026-4100")
        VulnerabilitySource.objects.create(
            source_object=vulnerability_source,
            vulnerability=vulnerability,
        )
        deleted_finding_source = source_object(
            self.integration,
            "deleted-finding",
            "vulnerability_finding",
            deleted=True,
        )
        VulnerabilityFinding.objects.create(
            source_object=deleted_finding_source,
            asset=asset,
            vulnerability=vulnerability,
            status=VulnerabilityFinding.Status.OPEN,
        )

        technique_source = source_object(
            self.integration,
            "aggregate-technique",
            "attack_technique",
        )
        technique = AttackTechnique.objects.create(
            technique_id="T4100",
            name="Aggregate technique",
            source_object=technique_source,
        )
        deleted_detection_source = source_object(
            self.integration,
            "deleted-detection",
            "detection_rule",
            deleted=True,
        )
        detection = DetectionRule.objects.create(
            source_object=deleted_detection_source,
            integration=self.integration,
            external_id="deleted-detection",
            name="Deleted detection",
            enabled=True,
        )
        detection.techniques.add(technique)

        api = self.api_for(self.reader)
        asset_payload = api.get(f"/api/catalog/assets/{asset.pk}/").json()
        vulnerability_payload = api.get(
            f"/api/catalog/vulnerabilities/{vulnerability.pk}/"
        ).json()
        technique_payload = api.get(
            f"/api/catalog/attack-techniques/{technique.pk}/"
        ).json()

        self.assertEqual(asset_payload["software_count"], 0)
        self.assertEqual(asset_payload["open_vulnerability_count"], 0)
        self.assertEqual(vulnerability_payload["open_finding_count"], 0)
        self.assertEqual(technique_payload["detection_count"], 0)

    def test_dashboard_and_report_counts_exclude_deleted_provenance(self):
        technique = AttackTechnique.objects.create(
            technique_id="T4200",
            name="Counted technique",
        )
        active_report_source = source_object(
            self.integration,
            "active-count-report",
            "threat_report",
        )
        active_report = ThreatReport.objects.create(
            source_object=active_report_source,
            integration=self.integration,
            external_id="active-count-report",
            title="Active count report",
        )
        ThreatReportTechnique.objects.create(
            report=active_report,
            technique=technique,
            review_status=ThreatReportTechnique.ReviewStatus.APPROVED,
        )

        deleted_report_source = source_object(
            self.integration,
            "deleted-count-report",
            "threat_report",
            deleted=True,
        )
        deleted_report = ThreatReport.objects.create(
            source_object=deleted_report_source,
            integration=self.integration,
            external_id="deleted-count-report",
            title="Deleted count report",
        )
        ThreatReportTechnique.objects.create(
            report=deleted_report,
            technique=technique,
            review_status=ThreatReportTechnique.ReviewStatus.PENDING,
        )

        deleted_detection_source = source_object(
            self.integration,
            "deleted-report-detection",
            "detection_rule",
            deleted=True,
        )
        deleted_detection = DetectionRule.objects.create(
            source_object=deleted_detection_source,
            integration=self.integration,
            external_id="deleted-report-detection",
            name="Deleted report detection",
        )
        deleted_detection.techniques.add(technique)

        browser = Client()
        browser.force_login(self.reader)
        dashboard_response = browser.get("/")
        self.assertEqual(dashboard_response.context["pending_review_count"], 0)
        self.assertEqual(dashboard_response.context["report_count"], 1)

        report_response = browser.get(f"/reports/{active_report.pk}/")
        link = list(report_response.context["report"].technique_links.all())[0]
        self.assertEqual(link.technique.detection_rules.count(), 0)

    def test_nested_relationships_exclude_deleted_child_provenance(self):
        active_technique_source = source_object(
            self.integration,
            "active-nested-technique",
            "attack_technique",
        )
        active_technique = AttackTechnique.objects.create(
            technique_id="T4300",
            name="Active nested technique",
            source_object=active_technique_source,
        )
        deleted_technique_source = source_object(
            self.integration,
            "deleted-nested-technique",
            "attack_technique",
            deleted=True,
        )
        deleted_technique = AttackTechnique.objects.create(
            technique_id="T4301",
            name="Deleted nested technique",
            source_object=deleted_technique_source,
        )
        detection_source = source_object(
            self.integration,
            "active-nested-detection",
            "detection_rule",
        )
        detection = DetectionRule.objects.create(
            source_object=detection_source,
            integration=self.integration,
            external_id="active-nested-detection",
            name="Active nested detection",
        )
        detection.techniques.add(active_technique, deleted_technique)

        active_telemetry_source = source_object(
            self.integration,
            "active-nested-telemetry",
            "telemetry_source",
        )
        active_telemetry = TelemetrySource.objects.create(
            key="active-nested-telemetry",
            name="Active nested telemetry",
            source_object=active_telemetry_source,
        )
        deleted_telemetry_source = source_object(
            self.integration,
            "deleted-nested-telemetry",
            "telemetry_source",
            deleted=True,
        )
        deleted_telemetry = TelemetrySource.objects.create(
            key="deleted-nested-telemetry",
            name="Deleted nested telemetry",
            source_object=deleted_telemetry_source,
        )
        DetectionRuleTelemetry.objects.create(
            detection_rule=detection,
            telemetry_source=active_telemetry,
        )
        DetectionRuleTelemetry.objects.create(
            detection_rule=detection,
            telemetry_source=deleted_telemetry,
        )

        validation_test_source = source_object(
            self.integration,
            "active-nested-test",
            "validation_test",
        )
        validation_test = ValidationTest.objects.create(
            source_object=validation_test_source,
            integration=self.integration,
            external_id="active-nested-test",
            name="Active nested test",
        )
        validation_test.techniques.add(active_technique, deleted_technique)

        api = self.api_for(self.reader)
        detection_payload = api.get(
            f"/api/catalog/detection-rules/{detection.pk}/"
        ).json()
        test_payload = api.get(
            f"/api/catalog/validation-tests/{validation_test.pk}/"
        ).json()

        self.assertEqual(
            {item["technique_id"] for item in detection_payload["techniques"]},
            {"T4300"},
        )
        self.assertEqual(
            {item["name"] for item in detection_payload["telemetry_sources"]},
            {"Active nested telemetry"},
        )
        self.assertEqual(
            {item["technique_id"] for item in test_payload["techniques"]},
            {"T4300"},
        )

    def test_validation_result_visibility_requires_active_related_provenance(self):
        active_test_source = source_object(
            self.integration,
            "active-visible-test",
            "validation_test",
        )
        active_test = ValidationTest.objects.create(
            source_object=active_test_source,
            integration=self.integration,
            external_id="active-visible-test",
            name="Active visible test",
        )
        visible_result_source = source_object(
            self.integration,
            "visible-result",
            "validation_result",
        )
        visible_result = ValidationResult.objects.create(
            source_object=visible_result_source,
            test=active_test,
            outcome=ValidationResult.Outcome.PASSED,
        )

        deleted_test_source = source_object(
            self.integration,
            "deleted-related-test",
            "validation_test",
            deleted=True,
        )
        deleted_test = ValidationTest.objects.create(
            source_object=deleted_test_source,
            integration=self.integration,
            external_id="deleted-related-test",
            name="Deleted related test",
        )
        hidden_test_result_source = source_object(
            self.integration,
            "hidden-test-result",
            "validation_result",
        )
        ValidationResult.objects.create(
            source_object=hidden_test_result_source,
            test=deleted_test,
            outcome=ValidationResult.Outcome.PASSED,
        )

        deleted_detection_source = source_object(
            self.integration,
            "deleted-related-detection",
            "detection_rule",
            deleted=True,
        )
        deleted_detection = DetectionRule.objects.create(
            source_object=deleted_detection_source,
            integration=self.integration,
            external_id="deleted-related-detection",
            name="Deleted related detection",
        )
        hidden_detection_result_source = source_object(
            self.integration,
            "hidden-detection-result",
            "validation_result",
        )
        ValidationResult.objects.create(
            source_object=hidden_detection_result_source,
            test=active_test,
            detection_rule=deleted_detection,
            outcome=ValidationResult.Outcome.PASSED,
        )

        response = self.api_for(self.reader).get("/api/catalog/validation-results/")
        result_ids = {item["id"] for item in response.json()["results"]}
        self.assertEqual(result_ids, {visible_result.pk})

    def test_assessment_selection_ignores_deleted_related_provenance(self):
        report_source = source_object(
            self.integration,
            "assessment-selection-report",
            "threat_report",
        )
        report = ThreatReport.objects.create(
            source_object=report_source,
            integration=self.integration,
            external_id="assessment-selection-report",
            title="Assessment selection report",
        )
        technique = AttackTechnique.objects.create(
            technique_id="T4400",
            name="Assessment selection technique",
        )
        ThreatReportTechnique.objects.create(
            report=report,
            technique=technique,
            review_status=ThreatReportTechnique.ReviewStatus.APPROVED,
        )
        detection_source = source_object(
            self.integration,
            "assessment-selection-detection",
            "detection_rule",
        )
        detection = DetectionRule.objects.create(
            source_object=detection_source,
            integration=self.integration,
            external_id="assessment-selection-detection",
            name="Assessment selection detection",
        )
        detection.techniques.add(technique)

        deleted_test_source = source_object(
            self.integration,
            "assessment-deleted-test",
            "validation_test",
            deleted=True,
        )
        deleted_test = ValidationTest.objects.create(
            source_object=deleted_test_source,
            integration=self.integration,
            external_id="assessment-deleted-test",
            name="Assessment deleted test",
        )
        result_source = source_object(
            self.integration,
            "assessment-hidden-result",
            "validation_result",
        )
        ValidationResult.objects.create(
            source_object=result_source,
            test=deleted_test,
            technique=technique,
            detection_rule=detection,
            outcome=ValidationResult.Outcome.PASSED,
        )

        assessment = generate_assessment(
            report,
            actor=self.assessor,
            origin="test:deleted_provenance_selection",
        )

        finding = assessment.findings.get()
        self.assertEqual(finding.state, "detection_documented")
        self.assertTrue(assessment.evidence_provenance_complete)
        self.assertFalse(assessment.evidence_sources.filter(is_deleted=True).exists())
        self.assertNotIn(
            deleted_test_source.pk,
            assessment.evidence_sources.values_list("pk", flat=True),
        )
        self.assertNotIn(
            result_source.pk,
            assessment.evidence_sources.values_list("pk", flat=True),
        )

    def test_provenance_completeness_fails_closed_for_deleted_candidates(self):
        report_source = source_object(
            self.integration,
            "completeness-report",
            "threat_report",
        )
        report = ThreatReport.objects.create(
            source_object=report_source,
            integration=self.integration,
            external_id="completeness-report",
            title="Completeness report",
        )
        assessment = Assessment.objects.create(report=report, origin="test:completeness")
        active_candidate = source_object(
            self.integration,
            "active-completeness-candidate",
            "asset",
        )
        deleted_candidate = source_object(
            self.integration,
            "deleted-completeness-candidate",
            "asset",
            deleted=True,
        )

        with transaction.atomic():
            attach_active_assessment_provenance(
                assessment,
                {report_source.pk, active_candidate.pk, deleted_candidate.pk},
            )

        self.assertFalse(assessment.evidence_provenance_complete)
        self.assertEqual(
            set(assessment.evidence_sources.values_list("pk", flat=True)),
            {report_source.pk, active_candidate.pk},
        )


class IndirectAdminProvenanceRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.superuser = get_user_model().objects.create_superuser(
            "admin-provenance-superuser",
            email="admin-provenance-superuser@example.invalid",
        )
        cls.integration = Integration.objects.create(
            name="Admin provenance source",
            slug="admin-provenance-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )

    def admin_ids(self, model):
        model_admin = admin.site._registry[model]
        request = SimpleNamespace(user=self.superuser)
        return set(model_admin.get_queryset(request).values_list("pk", flat=True))

    def test_validation_results_findings_and_observables_require_active_parents(self):
        active_report_source = source_object(
            self.integration,
            "admin-active-report",
            "threat_report",
        )
        active_report = ThreatReport.objects.create(
            source_object=active_report_source,
            integration=self.integration,
            external_id="admin-active-report",
            title="Admin active report",
        )
        deleted_report_source = source_object(
            self.integration,
            "admin-deleted-report",
            "threat_report",
            deleted=True,
        )
        deleted_report = ThreatReport.objects.create(
            source_object=deleted_report_source,
            integration=self.integration,
            external_id="admin-deleted-report",
            title="Admin deleted report",
        )
        active_observable = Observable.objects.create(
            report=active_report,
            observable_type="domain",
            value="active.example.invalid",
        )
        Observable.objects.create(
            report=deleted_report,
            observable_type="domain",
            value="deleted.example.invalid",
        )

        active_assessment = Assessment.objects.create(
            report=active_report,
            evidence_provenance_complete=True,
            origin="test:active_admin_assessment",
        )
        active_assessment.evidence_sources.add(active_report_source)
        deleted_assessment = Assessment.objects.create(
            report=deleted_report,
            evidence_provenance_complete=True,
            origin="test:deleted_admin_assessment",
        )
        deleted_assessment.evidence_sources.add(deleted_report_source)
        active_finding = GapFinding.objects.create(
            assessment=active_assessment,
            category=GapFinding.Category.TECHNIQUE,
            state=GapFinding.State.DETECTION_MISSING,
            title="Active admin finding",
        )
        GapFinding.objects.create(
            assessment=deleted_assessment,
            category=GapFinding.Category.TECHNIQUE,
            state=GapFinding.State.DETECTION_MISSING,
            title="Deleted admin finding",
        )

        active_test_source = source_object(
            self.integration,
            "admin-active-test",
            "validation_test",
        )
        active_test = ValidationTest.objects.create(
            source_object=active_test_source,
            integration=self.integration,
            external_id="admin-active-test",
            name="Admin active test",
        )
        active_result_source = source_object(
            self.integration,
            "admin-active-result",
            "validation_result",
        )
        active_result = ValidationResult.objects.create(
            source_object=active_result_source,
            test=active_test,
            outcome=ValidationResult.Outcome.PASSED,
        )
        deleted_test_source = source_object(
            self.integration,
            "admin-deleted-test",
            "validation_test",
            deleted=True,
        )
        deleted_test = ValidationTest.objects.create(
            source_object=deleted_test_source,
            integration=self.integration,
            external_id="admin-deleted-test",
            name="Admin deleted test",
        )
        hidden_result_source = source_object(
            self.integration,
            "admin-hidden-result",
            "validation_result",
        )
        ValidationResult.objects.create(
            source_object=hidden_result_source,
            test=deleted_test,
            outcome=ValidationResult.Outcome.PASSED,
        )

        self.assertEqual(self.admin_ids(Observable), {active_observable.pk})
        self.assertEqual(self.admin_ids(GapFinding), {active_finding.pk})
        self.assertEqual(self.admin_ids(ValidationResult), {active_result.pk})

    def test_asset_alias_requires_active_asset_provenance(self):
        active_source = source_object(self.integration, "admin-active-asset", "asset")
        active_asset = Asset.objects.create(
            canonical_key="admin-active-asset",
            display_name="Admin active asset",
        )
        AssetSource.objects.create(source_object=active_source, asset=active_asset)
        active_alias = AssetAlias.objects.create(
            asset=active_asset,
            namespace="test",
            kind="hostname",
            value="active-host",
            normalized_value="active-host",
        )

        deleted_source = source_object(
            self.integration,
            "admin-deleted-asset",
            "asset",
            deleted=True,
        )
        deleted_asset = Asset.objects.create(
            canonical_key="admin-deleted-asset",
            display_name="Admin deleted asset",
        )
        AssetSource.objects.create(source_object=deleted_source, asset=deleted_asset)
        AssetAlias.objects.create(
            asset=deleted_asset,
            namespace="test",
            kind="hostname",
            value="deleted-host",
            normalized_value="deleted-host",
        )

        self.assertEqual(self.admin_ids(AssetAlias), {active_alias.pk})

    def test_detection_relationship_admin_requires_active_related_provenance(self):
        active_technique_source = source_object(
            self.integration,
            "admin-active-technique",
            "attack_technique",
        )
        active_technique = AttackTechnique.objects.create(
            technique_id="T4500",
            name="Admin active technique",
            source_object=active_technique_source,
        )
        deleted_technique_source = source_object(
            self.integration,
            "admin-deleted-technique",
            "attack_technique",
            deleted=True,
        )
        deleted_technique = AttackTechnique.objects.create(
            technique_id="T4501",
            name="Admin deleted technique",
            source_object=deleted_technique_source,
        )
        active_detection_source = source_object(
            self.integration,
            "admin-active-detection",
            "detection_rule",
        )
        active_detection = DetectionRule.objects.create(
            source_object=active_detection_source,
            integration=self.integration,
            external_id="admin-active-detection",
            name="Admin active detection",
        )
        deleted_detection_source = source_object(
            self.integration,
            "admin-deleted-detection",
            "detection_rule",
            deleted=True,
        )
        deleted_detection = DetectionRule.objects.create(
            source_object=deleted_detection_source,
            integration=self.integration,
            external_id="admin-deleted-detection",
            name="Admin deleted detection",
        )
        active_technique_link = DetectionRuleTechnique.objects.create(
            detection_rule=active_detection,
            technique=active_technique,
        )
        DetectionRuleTechnique.objects.create(
            detection_rule=active_detection,
            technique=deleted_technique,
        )
        DetectionRuleTechnique.objects.create(
            detection_rule=deleted_detection,
            technique=active_technique,
        )

        active_telemetry_source = source_object(
            self.integration,
            "admin-active-telemetry",
            "telemetry_source",
        )
        active_telemetry = TelemetrySource.objects.create(
            key="admin-active-telemetry",
            name="Admin active telemetry",
            source_object=active_telemetry_source,
        )
        deleted_telemetry_source = source_object(
            self.integration,
            "admin-deleted-telemetry",
            "telemetry_source",
            deleted=True,
        )
        deleted_telemetry = TelemetrySource.objects.create(
            key="admin-deleted-telemetry",
            name="Admin deleted telemetry",
            source_object=deleted_telemetry_source,
        )
        active_telemetry_link = DetectionRuleTelemetry.objects.create(
            detection_rule=active_detection,
            telemetry_source=active_telemetry,
        )
        DetectionRuleTelemetry.objects.create(
            detection_rule=active_detection,
            telemetry_source=deleted_telemetry,
        )
        DetectionRuleTelemetry.objects.create(
            detection_rule=deleted_detection,
            telemetry_source=active_telemetry,
        )

        self.assertEqual(
            self.admin_ids(DetectionRuleTechnique),
            {active_technique_link.pk},
        )
        self.assertEqual(
            self.admin_ids(DetectionRuleTelemetry),
            {active_telemetry_link.pk},
        )


class DeletedReportReviewRemediationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.reviewer = get_user_model().objects.create_user(
            "deleted-report-reviewer",
            password="test-password",
        )
        grant(cls.reviewer, "catalog", "review_attack_mapping")
        cls.integration = Integration.objects.create(
            name="Review provenance source",
            slug="review-provenance-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )
        cls.report_source = source_object(
            cls.integration,
            "deleted-review-report",
            "threat_report",
        )
        cls.report = ThreatReport.objects.create(
            source_object=cls.report_source,
            integration=cls.integration,
            external_id="deleted-review-report",
            title="Deleted review report",
        )
        cls.technique = AttackTechnique.objects.create(
            technique_id="T4600",
            name="Deleted review technique",
        )
        cls.mapping = ThreatReportTechnique.objects.create(
            report=cls.report,
            technique=cls.technique,
            review_status=ThreatReportTechnique.ReviewStatus.PENDING,
        )

    def test_direct_review_reloads_and_rejects_stale_deleted_report_provenance(self):
        stale_mapping = ThreatReportTechnique.objects.select_related(
            "report__source_object"
        ).get(pk=self.mapping.pk)
        ExternalObject.all_objects.filter(pk=self.report_source.pk).update(
            is_deleted=True
        )

        with self.assertRaisesRegex(ValueError, "Deleted report evidence"):
            transition_attack_mapping_review(
                stale_mapping,
                new_state=ThreatReportTechnique.ReviewStatus.APPROVED,
                actor=self.reviewer,
                reason="Attempted stale review",
                origin="test:deleted_report_review",
            )

        self.mapping.refresh_from_db()
        self.assertEqual(self.mapping.review_status, ThreatReportTechnique.ReviewStatus.PENDING)
        self.assertFalse(AttackMappingReviewEvent.objects.filter(mapping=self.mapping).exists())

    def test_browser_deleted_and_nonexistent_mapping_ids_are_indistinguishable(self):
        ExternalObject.all_objects.filter(pk=self.report_source.pk).update(
            is_deleted=True
        )
        browser = Client()
        browser.force_login(self.reviewer)
        deleted = browser.post(
            reverse("web-review-technique", args=[self.mapping.pk]),
            {
                "review_status": ThreatReportTechnique.ReviewStatus.APPROVED,
                "reason": "Deleted mapping review",
            },
        )
        nonexistent = browser.post(
            reverse("web-review-technique", args=[999999]),
            {
                "review_status": ThreatReportTechnique.ReviewStatus.APPROVED,
                "reason": "Unknown mapping review",
            },
        )

        self.assertEqual(deleted.status_code, 404)
        self.assertEqual(nonexistent.status_code, 404)
        self.mapping.refresh_from_db()
        self.assertEqual(self.mapping.review_status, ThreatReportTechnique.ReviewStatus.PENDING)
