from __future__ import annotations

from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.adapters.base import SyncContext
from integrations.adapters.opencti import OpenCtiReportsAdapter
from integrations.registry import available_adapters


class OpenCtiAdapterTests(SimpleTestCase):
    def setUp(self):
        self.context = SyncContext(
            integration_slug="opencti",
            configuration={"base_url": "https://opencti.example"},
            secret_reference="",
            secrets={"token": "synthetic-opencti-token"},
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

    def _response(self):
        return {
            "data": {
                "reports": {
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "edges": [],
                }
            }
        }

    @patch("integrations.adapters.opencti.request_json")
    def test_connection_is_read_only_bounded_and_uses_the_configured_origin(self, request):
        request.return_value = self._response()
        context = SyncContext(
            integration_slug="opencti",
            configuration={
                "base_url": "https://opencti.example.invalid/platform",
                "graphql_url": "https://opencti.example.invalid/platform/graphql",
                "timeout_seconds": 30,
            },
            secret_reference="env:OPENCTI_TOKEN",
            secrets={"token": "synthetic-opencti-token"},
        )

        result = OpenCtiReportsAdapter().test_connection(context)

        self.assertTrue(result["ok"])
        _args, kwargs = request.call_args
        self.assertEqual(_args, ("https://opencti.example.invalid/platform/graphql",))
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(
            kwargs["headers"],
            {"Authorization": "Bearer synthetic-opencti-token"},
        )
        self.assertNotIn("mutation", kwargs["json_body"]["query"].casefold())

    def test_cross_origin_graphql_override_is_rejected_before_request(self):
        context = SyncContext(
            integration_slug="opencti",
            configuration={
                "base_url": "https://opencti.example.invalid",
                "graphql_url": "https://other.example.invalid/graphql",
            },
            secret_reference="env:OPENCTI_TOKEN",
            secrets={"token": "synthetic-opencti-token"},
        )
        with self.assertRaisesRegex(ValueError, "configured base_url origin"):
            OpenCtiReportsAdapter().test_connection(context)

    @patch("integrations.adapters.opencti.request_json")
    def test_graphql_mutations_are_rejected_before_request(self, request):
        context = SyncContext(
            integration_slug="opencti",
            configuration={
                "base_url": "https://opencti.example.invalid",
                "query": "mutation UnsafeWrite { deleteReport(id: \"report--1\") }",
            },
            secret_reference="env:OPENCTI_TOKEN",
            secrets={"token": "synthetic-opencti-token"},
        )
        with self.assertRaisesRegex(ValueError, "read-only GraphQL query"):
            OpenCtiReportsAdapter().test_connection(context)
        request.assert_not_called()

    @patch("integrations.adapters.opencti.request_json")
    def test_graphql_errors_do_not_echo_vendor_text_or_token(self, request):
        request.return_value = {
            "errors": [{"message": "token synthetic-opencti-token was rejected"}]
        }
        context = SyncContext(
            integration_slug="opencti",
            configuration={"base_url": "https://opencti.example.invalid"},
            secret_reference="env:OPENCTI_TOKEN",
            secrets={"token": "synthetic-opencti-token"},
        )

        with self.assertRaises(ValueError) as raised:
            OpenCtiReportsAdapter().test_connection(context)
        self.assertEqual(str(raised.exception), "OpenCTI GraphQL request failed")
        self.assertNotIn("synthetic-opencti-token", str(raised.exception))

    @patch("integrations.adapters.opencti.request_json")
    def test_malformed_graphql_responses_fail_safely(self, request):
        malformed_responses = (
            {},
            {"data": None},
            {"data": {"reports": []}},
            {"data": {"reports": {"edges": [], "pageInfo": None}}},
            {
                "data": {
                    "reports": {
                        "edges": [{"node": "not-an-object"}],
                        "pageInfo": {"hasNextPage": False},
                    }
                }
            },
        )
        for response in malformed_responses:
            with self.subTest(response=response):
                request.return_value = response
                with self.assertRaisesRegex(ValueError, "response was malformed"):
                    OpenCtiReportsAdapter().test_connection(self.context)

    @patch("integrations.adapters.opencti.request_json")
    def test_page_size_and_timeout_are_bounded(self, request):
        request.return_value = self._response()
        for configuration, message, operation in (
            (
                {"base_url": "https://opencti.example", "timeout_seconds": 121},
                "timeout_seconds",
                "test",
            ),
            (
                {"base_url": "https://opencti.example", "page_size": 501},
                "page_size",
                "pull",
            ),
        ):
            with self.subTest(configuration=configuration):
                context = SyncContext(
                    integration_slug="opencti",
                    configuration=configuration,
                    secret_reference="",
                    secrets={"token": "synthetic-opencti-token"},
                )
                with self.assertRaisesRegex(ValueError, message):
                    if operation == "test":
                        OpenCtiReportsAdapter().test_connection(context)
                    else:
                        OpenCtiReportsAdapter().pull(context, {})

    def test_mvp_adapter_catalog_excludes_microsoft_defender(self):
        adapter_paths = {adapter["adapter_path"] for adapter in available_adapters()}
        self.assertNotIn(
            "integrations.adapters.defender_vm.DefenderVmAdapter",
            adapter_paths,
        )
