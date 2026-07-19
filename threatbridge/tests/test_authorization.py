from __future__ import annotations

import hashlib
from types import SimpleNamespace

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from rest_framework.test import APIClient

from catalog.admin import ThreatReportTechniqueInline
from catalog.models import (
    Assessment,
    Asset,
    AssetSource,
    AttackMappingReviewEvent,
    AttackTechnique,
    SecurityAuditEvent,
    ThreatReport,
    ThreatReportTechnique,
    ThreatReportVulnerability,
    Vulnerability,
    VulnerabilityFinding,
)
from catalog.serializers import ManualThreatReportSerializer, ThreatReportTechniqueSerializer
from catalog.services.assess import generate_assessment
from catalog.services.audit import record_security_event
from catalog.services.review import transition_attack_mapping_review
from integrations.adapters.base import SourceRecord
from integrations.admin import ExternalObjectAdmin, IntegrationAdmin, IntegrationAdminForm
from integrations.evidence import delete_source_evidence, restore_source_evidence
from integrations.models import ExternalObject, Integration
from integrations.serializers import IntegrationSerializer
from integrations.services import ingest_source_record, project_external_object


class AuthorizationMatrixTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user_model = get_user_model()
        cls.ordinary = user_model.objects.create_user("ordinary", password="test-password")
        cls.importer = user_model.objects.create_user("importer", password="test-password")
        cls.operator = user_model.objects.create_user("operator", password="test-password")
        cls.assessor = user_model.objects.create_user("assessor", password="test-password")
        cls.reviewer = user_model.objects.create_user("reviewer", password="test-password")
        cls.auditor = user_model.objects.create_user("auditor", password="test-password")
        cls.restorer = user_model.objects.create_user("restorer", password="test-password")
        cls.staff = user_model.objects.create_user(
            "staff-only",
            password="test-password",
            is_staff=True,
        )
        cls.superuser = user_model.objects.create_superuser(
            "superuser",
            password="test-password",
            email="superuser@example.invalid",
        )

        cls._grant(cls.importer, "integrations", "import_source_file")
        for codename in (
            "view_integration",
            "configure_integration",
            "test_integration",
            "synchronize_integration",
        ):
            cls._grant(cls.operator, "integrations", codename)
        cls._grant(cls.assessor, "catalog", "run_assessment")
        cls._grant(cls.reviewer, "catalog", "review_attack_mapping")
        for codename in (
            "view_restricted_source_evidence",
            "view_deleted_source_evidence",
            "delete_source_evidence",
        ):
            cls._grant(cls.auditor, "integrations", codename)
        for codename in (
            "view_restricted_source_evidence",
            "view_deleted_source_evidence",
            "restore_deleted_source_evidence",
        ):
            cls._grant(cls.restorer, "integrations", codename)

        cls.integration = Integration.objects.create(
            name="Demo integration",
            slug="authorization-demo",
            kind=Integration.Kind.THREAT_INTELLIGENCE,
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )
        cls.report_source = cls._source(
            cls.integration,
            object_type="threat_report",
            external_id="report-authorization",
        )
        cls.report = ThreatReport.objects.create(
            source_object=cls.report_source,
            integration=cls.integration,
            external_id="report-authorization",
            title="Authorization report",
        )
        cls.technique = AttackTechnique.objects.create(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
        )
        cls.mapping = ThreatReportTechnique.objects.create(
            report=cls.report,
            technique=cls.technique,
            review_status=ThreatReportTechnique.ReviewStatus.PENDING,
        )

    @classmethod
    def _grant(cls, user, app_label: str, codename: str):
        user.user_permissions.add(
            Permission.objects.get(
                content_type__app_label=app_label,
                codename=codename,
            )
        )

    @classmethod
    def _source(cls, integration, *, object_type: str, external_id: str):
        return ExternalObject.objects.create(
            integration=integration,
            object_type=object_type,
            external_id=external_id,
            raw={"record": external_id},
            normalized={"record": external_id},
            content_hash=hashlib.sha256(external_id.encode()).hexdigest(),
        )

    def _api_for(self, user):
        client = APIClient()
        client.force_authenticate(user)
        return client

    def test_staff_alone_cannot_run_application_workflows(self):
        browser = Client()
        browser.force_login(self.staff)
        browser_cases = (
            ("get", "/imports/new/"),
            ("post", f"/integrations/{self.integration.pk}/test/"),
            ("post", f"/integrations/{self.integration.pk}/sync/"),
            ("post", f"/reports/{self.report.pk}/assess/"),
            ("post", f"/report-techniques/{self.mapping.pk}/review/"),
        )
        for method, path in browser_cases:
            with self.subTest(surface="browser", path=path):
                response = getattr(browser, method)(path)
                self.assertEqual(response.status_code, 403)

        api = self._api_for(self.staff)
        api_cases = (
            ("post", "/api/file-imports/"),
            ("post", f"/api/integrations/{self.integration.pk}/test/"),
            ("post", f"/api/integrations/{self.integration.pk}/sync/"),
            ("post", f"/api/catalog/threat-reports/{self.report.pk}/assess/"),
            ("post", f"/api/catalog/threat-report-techniques/{self.mapping.pk}/approve/"),
        )
        for method, path in api_cases:
            with self.subTest(surface="rest", path=path):
                response = getattr(api, method)(path)
                self.assertEqual(response.status_code, 403)

    def test_ordinary_user_is_read_only(self):
        api = self._api_for(self.ordinary)
        self.assertEqual(api.get("/api/catalog/threat-reports/").status_code, 200)
        self.assertEqual(
            api.post(
                "/api/catalog/threat-reports/manual/",
                {"title": "Unauthorized mutation"},
                format="json",
            ).status_code,
            403,
        )
        self.assertEqual(
            api.patch(
                f"/api/catalog/threat-report-techniques/{self.mapping.pk}/",
                {"review_status": "approved"},
                format="json",
            ).status_code,
            405,
        )
        self.assertEqual(api.get("/api/catalog/security-audit-events/").status_code, 403)

    def test_anonymous_user_has_no_application_data_access(self):
        browser = Client()
        self.assertEqual(browser.get("/reports/").status_code, 302)

        api = APIClient()
        self.assertIn(
            api.get("/api/catalog/threat-reports/").status_code,
            {401, 403},
        )
        self.assertEqual(api.get("/api/integrations/").status_code, 403)

    def test_named_permissions_allow_their_workflows(self):
        importer = Client()
        importer.force_login(self.importer)
        preview = importer.post(
            "/imports/preview/",
            {
                "file": SimpleUploadedFile(
                    "assets.csv",
                    b"device_id,device_name\nasset-1,server.example.invalid\n",
                    content_type="text/csv",
                ),
                "object_type": "auto",
            },
        )
        self.assertEqual(preview.status_code, 200)

        operator = self._api_for(self.operator)
        self.assertEqual(operator.get("/api/integrations/").status_code, 200)
        self.assertEqual(
            operator.post(f"/api/integrations/{self.integration.pk}/test/").status_code,
            200,
        )
        self.assertEqual(
            operator.post(f"/api/integrations/{self.integration.pk}/sync/").status_code,
            201,
        )

        assessor = self._api_for(self.assessor)
        self.assertEqual(
            assessor.post(
                f"/api/catalog/threat-reports/{self.report.pk}/assess/"
            ).status_code,
            201,
        )
        reviewer = self._api_for(self.reviewer)
        self.assertEqual(
            reviewer.post(
                f"/api/catalog/threat-report-techniques/{self.mapping.pk}/approve/",
                {"reason": "Validated against source evidence"},
                format="json",
            ).status_code,
            200,
        )
        event_types = set(SecurityAuditEvent.objects.values_list("event_type", flat=True))
        self.assertTrue(
            {
                "integration.test_started",
                "integration.test_completed",
                "integration.sync_started",
                "integration.sync_completed",
                "assessment.started",
                "assessment.completed",
                "attack_mapping.reviewed",
            }.issubset(event_types)
        )

    def test_superuser_retains_workflow_access(self):
        api = self._api_for(self.superuser)
        response = api.post(
            f"/api/catalog/threat-report-techniques/{self.mapping.pk}/reject/",
            {"reason": "Insufficient evidence"},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["review_status"], "rejected")
        self.assertEqual(
            api.get("/api/catalog/security-audit-events/").status_code,
            200,
        )

    def test_restricted_object_existence_is_not_disclosed(self):
        ordinary = self._api_for(self.ordinary)
        statuses = {
            ordinary.get(f"/api/external-objects/{self.report_source.pk}/").status_code,
            ordinary.get("/api/external-objects/999999/").status_code,
        }
        self.assertEqual(statuses, {403})

        auditor = self._api_for(self.auditor)
        restore_statuses = {
            auditor.post(f"/api/external-objects/{self.report_source.pk}/restore/").status_code,
            auditor.post("/api/external-objects/999999/restore/").status_code,
        }
        self.assertEqual(restore_statuses, {403})

    def test_importer_cannot_enumerate_or_replace_existing_profiles(self):
        profile = Integration.objects.create(
            name="Restricted import profile",
            slug="restricted-import-profile",
            adapter_path="integrations.adapters.csv_inventory.CsvInventoryAdapter",
        )
        browser = Client()
        browser.force_login(self.importer)
        response = browser.get("/imports/new/")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, profile.name)

        api = self._api_for(self.importer)
        statuses = set()
        for identifier in (profile.pk, 999999):
            response = api.post(
                "/api/file-imports/",
                {
                    "file": SimpleUploadedFile(
                        "assets.csv",
                        b"device_id,device_name\nasset-1,server.example.invalid\n",
                        content_type="text/csv",
                    ),
                    "integration_id": identifier,
                },
                format="multipart",
            )
            statuses.add(response.status_code)
        self.assertEqual(statuses, {403})

    def test_session_api_mutation_remains_csrf_protected(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.importer)
        response = client.post(
            "/api/file-imports/",
            {
                "file": SimpleUploadedFile(
                    "assets.csv",
                    b"device_id,device_name\nasset-1,server.example.invalid\n",
                    content_type="text/csv",
                )
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_mapping_review_is_centralized_pending_and_append_only(self):
        serializer = ManualThreatReportSerializer(
            data={
                "title": "Attempted self-approval",
                "techniques": [{"technique_id": "T1059", "review_status": "approved"}],
            }
        )
        self.assertFalse(serializer.is_valid())

        mapping_serializer = ThreatReportTechniqueSerializer(
            self.mapping,
            data={"review_status": "approved"},
            partial=True,
        )
        self.assertTrue(mapping_serializer.is_valid())
        self.assertNotIn("review_status", mapping_serializer.validated_data)

        reviewed = transition_attack_mapping_review(
            self.mapping,
            new_state=ThreatReportTechnique.ReviewStatus.APPROVED,
            actor=self.reviewer,
            reason="Reviewed evidence",
            origin="test:review",
        )
        event = AttackMappingReviewEvent.objects.get(mapping=reviewed)
        self.assertEqual(event.previous_state, "pending")
        self.assertEqual(event.new_state, "approved")
        self.assertEqual(event.actor, self.reviewer)
        self.assertEqual(event.reason, "Reviewed evidence")
        with self.assertRaises(ValidationError):
            event.save()
        with self.assertRaises(ValidationError):
            event.delete()

        response = self._api_for(self.reviewer).post(
            f"/api/catalog/threat-report-techniques/{self.mapping.pk}/reject/",
            {"reason": ""},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    def test_import_and_reprojection_force_mapping_back_to_pending(self):
        record = SourceRecord(
            external_id="pending-import-report",
            object_type="threat_report",
            natural_key="Pending import report",
            raw={"title": "Pending import report"},
            normalized={
                "title": "Pending import report",
                "techniques": [
                    {"technique_id": "T1059", "review_status": "approved"}
                ],
            },
        )
        source, _, _, imported_report = ingest_source_record(
            self.integration,
            record,
            actor=self.superuser,
            origin="test:manual_import",
        )
        imported_mapping = imported_report.technique_links.get()
        self.assertEqual(imported_mapping.review_status, "pending")
        transition_attack_mapping_review(
            imported_mapping,
            new_state="approved",
            actor=self.reviewer,
            reason="Initial review",
            origin="test:review",
        )

        project_external_object(
            source,
            actor=self.superuser,
            origin="test:reprojection",
        )

        self.assertEqual(imported_report.technique_links.get().review_status, "pending")

    def test_admin_metadata_prevents_direct_workflow_and_secret_edits(self):
        inline = ThreatReportTechniqueInline(ThreatReport, admin.site)
        self.assertIn("review_status", inline.readonly_fields)
        self.assertFalse(inline.has_add_permission(None))

        external_admin = ExternalObjectAdmin(ExternalObject, admin.site)
        self.assertNotIn("raw", external_admin.fields)
        self.assertNotIn("normalized", external_admin.fields)
        integration_admin = IntegrationAdmin(Integration, admin.site)
        self.assertIs(integration_admin.form, IntegrationAdminForm)
        self.assertFalse(
            integration_admin.form.base_fields[
                "secret_reference"
            ].widget.render_value
        )

        auth_staff = get_user_model().objects.create_user(
            "auth-model-staff",
            is_staff=True,
        )
        self._grant(auth_staff, "auth", "change_user")
        user_admin = admin.site._registry[get_user_model()]
        self.assertFalse(
            user_admin.has_change_permission(SimpleNamespace(user=auth_staff))
        )
        self.assertTrue(
            user_admin.has_change_permission(SimpleNamespace(user=self.superuser))
        )

    def test_integration_configuration_rejects_and_redacts_secret_values(self):
        serializer = IntegrationSerializer(
            data={
                "name": "Unsafe configuration",
                "slug": "unsafe-configuration",
                "adapter_path": "integrations.adapters.demo.DemoAdapter",
                "configuration": {"nested": {"token": "must-not-be-stored"}},
            }
        )
        self.assertFalse(serializer.is_valid())

        legacy = Integration.objects.create(
            name="Legacy configuration",
            slug="legacy-configuration",
            adapter_path="integrations.adapters.demo.DemoAdapter",
            configuration={"nested": {"token": "must-not-be-rendered"}},
            secret_reference="env:REFERENCE_NAME",
        )
        api_data = IntegrationSerializer(legacy).data
        self.assertEqual(api_data["configuration"]["nested"]["token"], "<redacted>")
        self.assertNotIn("secret_reference", api_data)
        self.assertNotIn("cursor", api_data)

        admin_form = IntegrationAdminForm(instance=legacy)
        rendered = admin_form.as_p()
        self.assertNotIn("must-not-be-rendered", rendered)
        self.assertNotIn("env:REFERENCE_NAME", rendered)


class EvidenceLifecycleAndAuditTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user_model = get_user_model()
        cls.assessor = user_model.objects.create_user("evidence-assessor")
        cls.auditor = user_model.objects.create_user("evidence-auditor")
        cls.restorer = user_model.objects.create_user("evidence-restorer")
        cls.superuser = user_model.objects.create_superuser(
            "evidence-superuser",
            email="evidence-superuser@example.invalid",
        )
        for user, permissions in (
            (cls.assessor, (("catalog", "run_assessment"),)),
            (
                cls.auditor,
                (
                    ("integrations", "view_restricted_source_evidence"),
                    ("integrations", "view_deleted_source_evidence"),
                    ("integrations", "delete_source_evidence"),
                ),
            ),
            (
                cls.restorer,
                (
                    ("integrations", "view_restricted_source_evidence"),
                    ("integrations", "view_deleted_source_evidence"),
                    ("integrations", "restore_deleted_source_evidence"),
                ),
            ),
        ):
            for app_label, codename in permissions:
                user.user_permissions.add(
                    Permission.objects.get(
                        content_type__app_label=app_label,
                        codename=codename,
                    )
                )

        cls.integration = Integration.objects.create(
            name="Evidence source",
            slug="evidence-source",
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )
        cls.report_source = cls._source("report", "threat_report")
        cls.report = ThreatReport.objects.create(
            source_object=cls.report_source,
            integration=cls.integration,
            external_id="report",
            title="Evidence lifecycle report",
        )
        cls.vulnerability = Vulnerability.objects.create(cve_id="CVE-2026-1000")
        ThreatReportVulnerability.objects.create(
            report=cls.report,
            vulnerability=cls.vulnerability,
        )
        cls.asset_source = cls._source("asset", "asset")
        cls.asset = Asset.objects.create(
            canonical_key="asset:evidence",
            display_name="Evidence asset",
        )
        AssetSource.objects.create(source_object=cls.asset_source, asset=cls.asset)
        cls.finding_source = cls._source("finding", "vulnerability_finding")
        VulnerabilityFinding.objects.create(
            source_object=cls.finding_source,
            asset=cls.asset,
            vulnerability=cls.vulnerability,
            status=VulnerabilityFinding.Status.OPEN,
        )

    @classmethod
    def _source(cls, external_id: str, object_type: str):
        return ExternalObject.objects.create(
            integration=cls.integration,
            object_type=object_type,
            external_id=external_id,
            raw={"sensitive_source": external_id},
            normalized={"external_id": external_id},
            content_hash=hashlib.sha256(external_id.encode()).hexdigest(),
        )

    def test_deleted_evidence_is_hidden_and_cannot_influence_assessment(self):
        before = generate_assessment(
            self.report,
            actor=self.assessor,
            origin="test:assessment_before_delete",
        )
        self.assertTrue(before.evidence_provenance_complete)
        self.assertEqual(before.findings.get().state, "exposure_confirmed")

        delete_source_evidence(
            self.finding_source,
            actor=self.auditor,
            reason="Source retracted the finding",
            origin="test:evidence_delete",
        )
        self.assertFalse(ExternalObject.objects.filter(pk=self.finding_source.pk).exists())
        self.assertTrue(ExternalObject.all_objects.get(pk=self.finding_source.pk).is_deleted)

        after = generate_assessment(
            self.report,
            actor=self.assessor,
            origin="test:assessment_after_delete",
        )
        self.assertEqual(after.findings.get().state, "exposure_not_found")

        ordinary = get_user_model().objects.create_user("evidence-reader")
        api = APIClient()
        api.force_authenticate(ordinary)
        self.assertEqual(
            api.get("/api/catalog/vulnerability-findings/").json()["count"],
            0,
        )
        self.assertEqual(
            api.get(f"/api/catalog/assessments/{before.pk}/").status_code,
            404,
        )
        with self.assertRaisesRegex(ValueError, "Deleted source evidence"):
            project_external_object(
                ExternalObject.all_objects.get(pk=self.finding_source.pk),
                actor=self.superuser,
                origin="test:deleted_reprojection",
            )

    def test_legacy_assessment_without_complete_provenance_is_hidden(self):
        legacy = Assessment.objects.create(
            report=self.report,
            status=Assessment.Status.SUCCEEDED,
            origin="unknown",
        )
        reader = get_user_model().objects.create_user("legacy-assessment-reader")
        api = APIClient()
        api.force_authenticate(reader)

        self.assertEqual(
            api.get(f"/api/catalog/assessments/{legacy.pk}/").status_code,
            404,
        )

    def test_deleted_asset_projection_is_not_enumerated(self):
        delete_source_evidence(
            self.asset_source,
            actor=self.auditor,
            reason="Asset source removed",
            origin="test:evidence_delete",
        )
        reader = get_user_model().objects.create_user("asset-reader")
        api = APIClient()
        api.force_authenticate(reader)
        self.assertEqual(api.get("/api/catalog/assets/").json()["count"], 0)

    def test_restore_requires_separate_permission_and_records_lifecycle(self):
        delete_source_evidence(
            self.asset_source,
            actor=self.auditor,
            reason="Temporary removal",
            origin="test:evidence_delete",
        )
        with self.assertRaises(PermissionDenied):
            restore_source_evidence(
                self.asset_source,
                actor=self.auditor,
                reason="Unauthorized restore",
                origin="test:evidence_restore",
            )
        restored = restore_source_evidence(
            self.asset_source,
            actor=self.restorer,
            reason="Auditor confirmed restoration",
            origin="test:evidence_restore",
        )
        self.assertFalse(restored.is_deleted)
        self.assertEqual(restored.deleted_by, self.auditor)
        self.assertEqual(restored.restored_by, self.restorer)
        self.assertEqual(restored.restoration_origin, "test:evidence_restore")

    def test_connector_ingest_does_not_resurrect_deleted_evidence(self):
        delete_source_evidence(
            self.asset_source,
            actor=self.auditor,
            reason="Retained deletion",
            origin="test:evidence_delete",
        )
        source, disposition, projection_status, projected = ingest_source_record(
            self.integration,
            SourceRecord(
                external_id=self.asset_source.external_id,
                object_type=self.asset_source.object_type,
                raw={"new": "record"},
                normalized={"asset_external_id": "asset", "hostname": "new.example.invalid"},
            ),
            actor=self.superuser,
            origin="test:connector_refresh",
        )
        source.refresh_from_db()
        self.assertTrue(source.is_deleted)
        self.assertEqual(disposition, "unchanged")
        self.assertIsNone(projection_status)
        self.assertIsNone(projected)

    def test_security_audit_metadata_is_redacted_and_append_only(self):
        event = record_security_event(
            event_type="test.redaction",
            origin="test:audit",
            outcome="succeeded",
            actor=self.auditor,
            target_type="test",
            target_identifier="1",
            metadata={
                "password": "do-not-store",
                "authorization": "Bearer do-not-store",
                "nested": {"token": "do-not-store"},
                "note": "Bearer do-not-store",
                "safe_count": 3,
            },
        )
        self.assertEqual(event.metadata["password"], "<redacted>")
        self.assertEqual(event.metadata["authorization"], "<redacted>")
        self.assertEqual(event.metadata["nested"]["token"], "<redacted>")
        self.assertEqual(event.metadata["note"], "<redacted>")
        self.assertEqual(event.metadata["safe_count"], 3)
        with self.assertRaises(ValidationError):
            event.save()
        with self.assertRaises(ValidationError):
            event.delete()

        event_types = set(SecurityAuditEvent.objects.values_list("event_type", flat=True))
        self.assertIn("test.redaction", event_types)
