from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from catalog.models import Asset, SecurityAuditEvent, ThreatReport, Vulnerability
from integrations.file_imports import create_file_import, inspect_uploaded_file
from integrations.models import ExternalObject, Integration, SyncRun


class FileImportTests(TestCase):
    def setUp(self):
        self.temporary_directory = TemporaryDirectory()
        self.override = override_settings(
            THREATBRIDGE_DATA_DIR=self.temporary_directory.name,
            THREATBRIDGE_MAX_UPLOAD_BYTES=2 * 1024 * 1024,
            THREATBRIDGE_MAX_IMPORT_RECORDS=1000,
        )
        self.override.enable()

    def tearDown(self):
        self.override.disable()
        self.temporary_directory.cleanup()

    def test_csv_preview_and_import_auto_map_assets(self):
        content = (
            b"device_id,device_name,operating_system,criticality,last_seen\n"
            b"device-1,server-01.example,Windows Server 2022,critical,2026-07-18T12:00:00Z\n"
            b"device-2,server-02.example,Linux,high,2026-07-18T12:05:00Z\n"
        )
        upload = SimpleUploadedFile("assets.csv", content, content_type="text/csv")

        inspection = inspect_uploaded_file(upload)

        self.assertEqual(inspection.file_format, "csv")
        self.assertEqual(inspection.record_count, 2)
        self.assertEqual(inspection.suggested_object_type, "asset")
        self.assertEqual(inspection.suggested_id_fields, ["device_id"])
        self.assertEqual(
            inspection.suggested_field_map["device_name"],
            "hostname",
        )

        result = create_file_import(
            uploaded_file=upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_accepted, 2)
        self.assertEqual(result.run.records_projected, 2)
        self.assertEqual(Asset.objects.count(), 2)
        self.assertEqual(ExternalObject.objects.count(), 2)
        self.assertEqual(
            result.integration.adapter_path,
            "integrations.adapters.csv_inventory.CsvInventoryAdapter",
        )
        self.assertTrue(result.stored_upload.absolute_path.is_file())

    def test_existing_file_profile_can_be_refreshed(self):
        first_upload = SimpleUploadedFile(
            "assets-one.csv",
            b"device_id,device_name,criticality\nasset-1,server-01.example,high\n",
            content_type="text/csv",
        )
        first = create_file_import(
            uploaded_file=first_upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )
        second_upload = SimpleUploadedFile(
            "assets-two.csv",
            b"device_id,device_name,criticality\nasset-2,server-02.example,critical\n",
            content_type="text/csv",
        )

        second = create_file_import(
            uploaded_file=second_upload,
            object_type="auto",
            integration=first.integration,
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(first.integration.pk, second.integration.pk)
        self.assertEqual(Integration.objects.count(), 1)
        self.assertEqual(second.run.records_projected, 1)
        self.assertEqual(Asset.objects.count(), 2)

    def test_wrapped_json_auto_detects_and_imports_threat_reports(self):
        payload = {
            "reports": [
                {
                    "report_id": "report-json-1",
                    "title": "Wrapped JSON threat report",
                    "summary": "Imported from a common reports wrapper.",
                    "source_name": "Example source",
                    "published_at": "2026-07-19T00:00:00Z",
                    "confidence": 85,
                    "tlp": "clear",
                    "targeted_industries": ["energy"],
                    "techniques": ["T1190"],
                    "vulnerabilities": ["CVE-2026-9999"],
                }
            ]
        }
        upload = SimpleUploadedFile(
            "threat-report.json",
            json.dumps(payload).encode(),
            content_type="application/json",
        )

        inspection = inspect_uploaded_file(upload)

        self.assertEqual(inspection.file_format, "json")
        self.assertEqual(inspection.records_key, "reports")
        self.assertEqual(inspection.suggested_object_type, "threat_report")
        self.assertEqual(inspection.suggested_id_fields, ["report_id"])

        result = create_file_import(
            uploaded_file=upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_projected, 1)
        self.assertEqual(ThreatReport.objects.count(), 1)
        self.assertEqual(ThreatReport.objects.get().external_id, "report-json-1")
        self.assertEqual(result.integration.configuration["records_key"], "reports")

    def test_json_lines_import_supports_dotted_source_paths(self):
        records = [
            {
                "device": {
                    "identity": {"id": "asset-jsonl-1"},
                    "name": "jsonl-server-01.example",
                    "platform": "Linux",
                },
                "criticality": "high",
            },
            {
                "device": {
                    "identity": {"id": "asset-jsonl-2"},
                    "name": "jsonl-server-02.example",
                    "platform": "Windows Server 2022",
                },
                "criticality": "critical",
            },
        ]
        upload = SimpleUploadedFile(
            "assets.jsonl",
            "\n".join(json.dumps(record) for record in records).encode(),
            content_type="application/x-ndjson",
        )

        result = create_file_import(
            uploaded_file=upload,
            object_type="asset",
            id_fields=["device.identity.id"],
            field_map={
                "device.identity.id": "asset_external_id",
                "device.name": "hostname",
                "device.platform": "os_platform",
                "criticality": "criticality",
            },
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_projected, 2)
        self.assertEqual(Asset.objects.count(), 2)
        self.assertTrue(
            Asset.objects.filter(
                aliases__kind="external_id",
                aliases__normalized_value="asset-jsonl-2",
                hostname="jsonl-server-02.example",
                criticality="critical",
            ).exists()
        )
        self.assertEqual(result.integration.configuration["format"], "jsonl")

    def test_nested_data_results_json_is_discovered_automatically(self):
        payload = {
            "data": {
                "results": [
                    {
                        "device_id": "asset-nested-1",
                        "device_name": "nested-server.example",
                        "criticality": "high",
                    }
                ]
            }
        }
        upload = SimpleUploadedFile(
            "nested-assets.json",
            json.dumps(payload).encode(),
            content_type="application/json",
        )

        inspection = inspect_uploaded_file(upload)
        self.assertEqual(inspection.records_key, "data.results")
        self.assertEqual(inspection.suggested_object_type, "asset")

        result = create_file_import(
            uploaded_file=upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )
        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertTrue(
            Asset.objects.filter(
                aliases__kind="external_id",
                aliases__normalized_value="asset-nested-1",
            ).exists()
        )

    def test_json_envelope_imports_mixed_object_types(self):
        payload = [
            {
                "external_id": "asset-1",
                "object_type": "asset",
                "natural_key": "server-01",
                "normalized": {
                    "asset_external_id": "asset-1",
                    "hostname": "server-01.example",
                    "criticality": "high",
                },
            },
            {
                "external_id": "vulnerability-cve-2026-9999",
                "object_type": "vulnerability",
                "natural_key": "CVE-2026-9999",
                "normalized": {
                    "cve_id": "CVE-2026-9999",
                    "title": "Example vulnerability",
                    "severity": "high",
                },
            },
        ]
        upload = SimpleUploadedFile(
            "threatbridge-envelope.json",
            json.dumps(payload).encode(),
            content_type="application/json",
        )

        result = create_file_import(
            uploaded_file=upload,
            object_type="mixed",
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_accepted, 2)
        self.assertEqual(Asset.objects.count(), 1)
        self.assertEqual(Vulnerability.objects.count(), 1)
        self.assertEqual(
            Vulnerability.objects.get().cve_id,
            "CVE-2026-9999",
        )
        self.assertEqual(result.integration.kind, Integration.Kind.GENERIC)

    def test_json_preview_and_import_auto_maps_camel_case_assets(self):
        payload = {
            "results": [
                {
                    "deviceId": "asset-json-1",
                    "deviceName": "json-server-01.example",
                    "platform": "Windows Server 2022",
                    "criticality": "critical",
                    "internetExposed": True,
                },
                {
                    "deviceId": "asset-json-2",
                    "deviceName": "json-server-02.example",
                    "platform": "Linux",
                    "criticality": "high",
                    "internetExposed": False,
                },
            ]
        }
        upload = SimpleUploadedFile(
            "assets.json",
            json.dumps(payload).encode(),
            content_type="application/json",
        )

        inspection = inspect_uploaded_file(upload)

        self.assertEqual(inspection.records_key, "results")
        self.assertEqual(inspection.suggested_object_type, "asset")
        self.assertEqual(inspection.suggested_id_fields, ["deviceId"])
        self.assertEqual(
            inspection.suggested_field_map,
            {
                "deviceId": "asset_external_id",
                "deviceName": "hostname",
                "platform": "os_platform",
                "criticality": "criticality",
                "internetExposed": "internet_exposed",
            },
        )

        result = create_file_import(
            uploaded_file=upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_projected, 2)
        self.assertEqual(Asset.objects.count(), 2)
        self.assertEqual(
            Asset.objects.get(hostname="json-server-01.example").internet_exposed,
            True,
        )

    def test_jsonl_preview_and_import_auto_maps_nested_assets(self):
        rows = [
            {
                "device": {
                    "identity": {"id": "asset-jsonl-1"},
                    "name": "jsonl-server-01.example",
                    "platform": "Linux",
                },
                "criticality": "high",
                "internet_exposed": False,
            },
            {
                "device": {
                    "identity": {"id": "asset-jsonl-2"},
                    "name": "jsonl-server-02.example",
                    "platform": "Windows Server 2022",
                },
                "criticality": "critical",
                "internet_exposed": True,
            },
        ]
        upload = SimpleUploadedFile(
            "assets.jsonl",
            "\n".join(json.dumps(row) for row in rows).encode(),
            content_type="application/x-ndjson",
        )

        inspection = inspect_uploaded_file(upload)

        self.assertEqual(inspection.suggested_object_type, "asset")
        self.assertEqual(inspection.suggested_id_fields, ["device.identity.id"])
        self.assertIn("device.name", inspection.fields)
        self.assertEqual(
            inspection.suggested_field_map["device.platform"],
            "os_platform",
        )

        result = create_file_import(
            uploaded_file=upload,
            object_type="auto",
            origin="management:test_file_import",
            system=True,
        )

        self.assertEqual(result.run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(result.run.records_projected, 2)
        self.assertEqual(Asset.objects.count(), 2)
        self.assertEqual(
            Asset.objects.get(hostname="jsonl-server-02.example").criticality,
            "critical",
        )

    def test_strict_partial_failure_retains_evidence_run_audit_and_upload(self):
        upload = SimpleUploadedFile(
            "strict-partial-assets.csv",
            (
                b"device_id,device_name\n"
                b"asset-persisted,retained.example.invalid\n"
                b",invalid.example.invalid\n"
            ),
            content_type="text/csv",
        )

        with self.assertRaises(RuntimeError):
            create_file_import(
                uploaded_file=upload,
                object_type="asset",
                id_fields=["device_id"],
                strict_records=True,
                origin="management:test_strict_partial_failure",
                system=True,
            )

        integration = Integration.objects.get()
        run = integration.sync_runs.get()
        stored_path = Path(self.temporary_directory.name) / integration.configuration["path"]
        self.assertFalse(integration.enabled)
        self.assertEqual(run.status, SyncRun.Status.FAILED)
        self.assertEqual(run.records_accepted, 1)
        self.assertEqual(
            ExternalObject.all_objects.filter(integration=integration).count(),
            1,
        )
        self.assertTrue(Asset.objects.filter(hostname="retained.example.invalid").exists())
        self.assertTrue(stored_path.is_file())
        self.assertEqual(
            set(
                SecurityAuditEvent.objects.filter(
                    origin="management:test_strict_partial_failure"
                ).values_list("event_type", flat=True)
            ),
            {
                "file_import.started",
                "file_import.completed",
                "integration.sync_started",
                "integration.sync_completed",
            },
        )


class FileImportEndpointTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from django.contrib.auth.models import Permission

        self.temporary_directory = TemporaryDirectory()
        self.override = override_settings(
            THREATBRIDGE_DATA_DIR=self.temporary_directory.name,
            THREATBRIDGE_MAX_UPLOAD_BYTES=2 * 1024 * 1024,
            THREATBRIDGE_MAX_IMPORT_RECORDS=1000,
        )
        self.override.enable()
        self.user = get_user_model().objects.create_user(
            username="file-import-admin",
            password="test-password",
            is_staff=True,
        )
        self.user.user_permissions.add(
            Permission.objects.get(
                content_type__app_label="integrations",
                codename="import_source_file",
            )
        )
        self.client.force_login(self.user)

    def tearDown(self):
        self.override.disable()
        self.temporary_directory.cleanup()

    @staticmethod
    def _asset_csv():
        return SimpleUploadedFile(
            "assets.csv",
            b"device_id,device_name,criticality\nasset-1,server-01.example,high\n",
            content_type="text/csv",
        )

    @staticmethod
    def _asset_json():
        return SimpleUploadedFile(
            "assets.json",
            json.dumps(
                {
                    "results": [
                        {
                            "deviceId": "asset-json-api-1",
                            "deviceName": "json-api-server.example",
                            "platform": "Linux",
                            "criticality": "high",
                        }
                    ]
                }
            ).encode(),
            content_type="application/json",
        )

    def test_import_page_renders_for_staff_user(self):
        response = self.client.get("/imports/new/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Import CSV or JSON")
        self.assertContains(response, "Preview and suggest mapping")

    def test_web_preview_returns_schema_suggestions(self):
        response = self.client.post(
            "/imports/preview/",
            {
                "file": self._asset_csv(),
                "object_type": "auto",
                "records_key": "",
                "delimiter": "",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["suggested_object_type"], "asset")
        self.assertEqual(payload["suggested_id_fields"], ["device_id"])

    def test_rest_upload_creates_and_synchronizes_profile(self):
        response = self.client.post(
            "/api/file-imports/",
            {
                "file": self._asset_csv(),
                "name": "Endpoint asset import",
                "object_type": "auto",
                "id_fields": "",
                "field_map": "{}",
                "sync_now": "true",
            },
        )

        self.assertEqual(response.status_code, 201, response.content)
        payload = response.json()
        self.assertEqual(payload["sync_run"]["status"], "succeeded")
        self.assertEqual(payload["sync_run"]["records_projected"], 1)
        self.assertEqual(Integration.objects.get().name, "Endpoint asset import")
        self.assertEqual(Asset.objects.count(), 1)
        self.assertTrue(
            {"file_import.started", "file_import.completed"}.issubset(
                SecurityAuditEvent.objects.values_list("event_type", flat=True)
            )
        )

    def test_rest_json_upload_auto_maps_camel_case_fields(self):
        response = self.client.post(
            "/api/file-imports/",
            {
                "file": self._asset_json(),
                "name": "Endpoint JSON asset import",
                "object_type": "auto",
                "id_fields": "",
                "field_map": "{}",
                "sync_now": "true",
            },
        )

        self.assertEqual(response.status_code, 201, response.content)
        payload = response.json()
        self.assertEqual(payload["inspection"]["suggested_id_fields"], ["deviceId"])
        self.assertEqual(payload["sync_run"]["records_projected"], 1)
        self.assertEqual(
            Asset.objects.get(hostname="json-api-server.example").os_platform,
            "Linux",
        )
