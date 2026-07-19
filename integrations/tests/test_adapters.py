from __future__ import annotations

from django.test import SimpleTestCase

from integrations.adapters.base import SyncContext
from integrations.adapters.opencti import OpenCtiReportsAdapter


class OpenCtiAdapterTests(SimpleTestCase):
    def setUp(self):
        self.context = SyncContext(
            integration_slug="opencti",
            configuration={"base_url": "https://opencti.example"},
            secret_reference="",
        )

    def test_normalize_includes_attack_cves_and_direct_markings(self):
        raw = {
            "id": "report--123",
            "name": "Example campaign report",
            "description": "A report with linked objects.",
            "published": "2026-07-18T18:30:00Z",
            "modified": "2026-07-19T00:00:00Z",
            "confidence": 85,
            "objectMarking": [
                {"definition": "TLP:AMBER"},
                {"definition": "TLP:AMBER"},
            ],
            "objects": {
                "edges": [
                    {
                        "node": {
                            "entity_type": "Attack-Pattern",
                            "name": "Exploit Public-Facing Application",
                            "x_mitre_id": "T1190",
                        }
                    },
                    {
                        "node": {
                            "entity_type": "Attack-Pattern",
                            "name": "PowerShell",
                            "x_mitre_id": "",
                            "externalReferences": {
                                "edges": [
                                    {
                                        "node": {
                                            "source_name": "mitre-attack",
                                            "external_id": "T1059.001",
                                        }
                                    }
                                ]
                            },
                        }
                    },
                    {
                        "node": {
                            "entity_type": "Vulnerability",
                            "name": "CVE-2026-9999",
                        }
                    },
                ]
            },
        }

        record = OpenCtiReportsAdapter().normalize(self.context, raw)

        self.assertEqual(record.external_id, "report--123")
        self.assertEqual(record.object_type, "threat_report")
        self.assertEqual(record.normalized["marking"], "TLP:AMBER")
        self.assertEqual(
            record.normalized["techniques"],
            [
                {
                    "attack_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                },
                {"attack_id": "T1059.001", "name": "PowerShell"},
            ],
        )
        self.assertEqual(
            record.normalized["vulnerabilities"],
            [{"cve_id": "CVE-2026-9999"}],
        )
        self.assertIsNotNone(record.source_updated_at)


class DefenderVmAdapterTests(SimpleTestCase):
    def setUp(self):
        from integrations.adapters.defender_vm import DefenderVmAdapter

        self.adapter = DefenderVmAdapter()
        self.software_context = SyncContext(
            integration_slug="defender-software",
            configuration={
                "resource": "software_inventory",
                "base_url": "https://api.security.microsoft.com",
            },
            secret_reference="",
        )
        self.vulnerability_context = SyncContext(
            integration_slug="defender-vulnerabilities",
            configuration={
                "resource": "vulnerabilities",
                "base_url": "https://api.security.microsoft.com",
            },
            secret_reference="",
        )

    def test_timezone_less_vendor_timestamp_is_treated_as_utc(self):
        record = self.adapter.normalize(
            self.software_context,
            {
                "deviceId": "device-1",
                "deviceName": "server-01.example",
                "softwareName": "Example Server",
                "softwareVendor": "Example",
                "softwareVersion": "1.0",
                "softwareFirstSeenTimestamp": "2026-07-18T12:00:00",
            },
        )

        self.assertIsNotNone(record.source_updated_at)
        self.assertEqual(record.source_updated_at.utcoffset().total_seconds(), 0)

    def test_vulnerability_normalization_keeps_device_cve_and_product(self):
        record = self.adapter.normalize(
            self.vulnerability_context,
            {
                "deviceId": "device-1",
                "deviceName": "server-01.example",
                "cveId": "cve-2026-9999",
                "softwareVendor": "Example",
                "softwareName": "Example Server",
                "softwareVersion": "1.0",
                "vulnerabilitySeverityLevel": "High",
                "lastSeenTimestamp": "2026-07-19T00:00:00Z",
            },
        )

        self.assertEqual(record.object_type, "vulnerability_finding")
        self.assertEqual(record.normalized["asset_external_id"], "device-1")
        self.assertEqual(record.normalized["cve_id"], "CVE-2026-9999")
        self.assertEqual(record.normalized["product"], "Example Server")
