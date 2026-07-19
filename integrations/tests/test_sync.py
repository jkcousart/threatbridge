from django.test import TestCase

from integrations.adapters.demo import DemoAdapter
from integrations.models import ExternalObject, Integration, SyncRun
from integrations.services import run_integration_sync


class SyncServiceTests(TestCase):
    def test_demo_sync_upserts_normalized_records_and_cursor(self):
        integration = Integration.objects.create(
            name="Demo Vulnerability Source",
            slug="demo-vulnerability",
            kind=Integration.Kind.VULNERABILITY,
            adapter_path="integrations.adapters.demo.DemoAdapter",
        )

        run = run_integration_sync(
            integration,
            origin="management:test_sync_service",
            system=True,
        )

        integration.refresh_from_db()
        expected_count = len(DemoAdapter.RECORDS)
        self.assertEqual(run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(run.records_received, expected_count)
        self.assertEqual(run.records_accepted, expected_count)
        self.assertEqual(run.records_rejected, 0)
        self.assertEqual(ExternalObject.objects.count(), expected_count)
        self.assertEqual(
            integration.cursor,
            {"complete": True, "record_count": expected_count},
        )

        second_run = run_integration_sync(
            integration,
            origin="management:test_sync_service",
            system=True,
        )
        self.assertEqual(ExternalObject.objects.count(), expected_count)
        self.assertEqual(second_run.records_unchanged, expected_count)
