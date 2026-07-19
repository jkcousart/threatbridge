from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.test import TestCase, override_settings

from catalog.models import Asset
from integrations.models import Integration, SyncRun


class ImportSourceFileCommandTests(TestCase):
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

    def test_imports_json_and_creates_reusable_profile(self):
        source = Path(self.temporary_directory.name) / "assets.json"
        source.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "deviceId": "device-command-1",
                            "deviceName": "command-server.example",
                            "platform": "Linux",
                            "criticality": "high",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        output = StringIO()

        call_command(
            "import_source_file",
            str(source),
            name="Command asset feed",
            stdout=output,
        )

        self.assertEqual(Integration.objects.count(), 1)
        run = SyncRun.objects.get()
        self.assertEqual(run.status, SyncRun.Status.SUCCEEDED)
        self.assertEqual(run.origin, "management:import_source_file")
        self.assertIsNone(run.initiated_by)
        self.assertEqual(Asset.objects.get().hostname, "command-server.example")
        self.assertIn("records=1", output.getvalue())
        self.assertIn("projected=1", output.getvalue())
