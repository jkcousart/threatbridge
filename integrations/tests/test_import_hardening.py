from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from integrations.file_imports import (
    _format_from_name,
    create_file_import,
    inspect_uploaded_file,
)


class HostileImportTests(TestCase):
    def setUp(self):
        self.temporary_directory = TemporaryDirectory()
        self.override = override_settings(
            THREATBRIDGE_DATA_DIR=self.temporary_directory.name,
            THREATBRIDGE_MAX_UPLOAD_BYTES=4096,
            THREATBRIDGE_MAX_IMPORT_RECORDS=10,
            THREATBRIDGE_MAX_JSON_DEPTH=6,
            THREATBRIDGE_MAX_OBJECT_FIELDS=10,
            THREATBRIDGE_MAX_FIELD_NAME_LENGTH=20,
            THREATBRIDGE_MAX_SCALAR_LENGTH=100,
            THREATBRIDGE_MAX_CSV_COLUMNS=10,
            THREATBRIDGE_MAX_CSV_FIELD_LENGTH=100,
            THREATBRIDGE_MAX_JSONL_LINE_BYTES=512,
            THREATBRIDGE_MAX_PREVIEW_SAMPLES=2,
            THREATBRIDGE_MAX_IMPORT_ERRORS=2,
        )
        self.override.enable()

    def tearDown(self):
        self.override.disable()
        self.temporary_directory.cleanup()

    @staticmethod
    def _upload(name: str, content: bytes, content_type: str):
        return SimpleUploadedFile(name, content, content_type=content_type)

    def test_upload_and_record_limits(self):
        with override_settings(THREATBRIDGE_MAX_UPLOAD_BYTES=16):
            with self.assertRaisesRegex(ValueError, "Maximum upload size"):
                inspect_uploaded_file(
                    self._upload(
                        "large.json",
                        b"{" + b" " * 20,
                        "application/json",
                    )
                )

        csv_content = b"device_id,device_name\n1,one\n2,two\n3,three\n"
        with override_settings(THREATBRIDGE_MAX_IMPORT_RECORDS=2):
            with self.assertRaisesRegex(ValueError, "record limit"):
                inspect_uploaded_file(self._upload("records.csv", csv_content, "text/csv"))

    def test_json_depth_field_name_object_and_scalar_limits(self):
        cases = (
            (
                {"a": {"b": {"c": {"d": "value"}}}},
                {"THREATBRIDGE_MAX_JSON_DEPTH": 2},
                "nesting",
            ),
            (
                {"one": 1, "two": 2, "three": 3},
                {"THREATBRIDGE_MAX_OBJECT_FIELDS": 2},
                "field limit",
            ),
            (
                {"field-name-too-long": "value"},
                {"THREATBRIDGE_MAX_FIELD_NAME_LENGTH": 5},
                "field name",
            ),
            (
                {"name": "123456"},
                {"THREATBRIDGE_MAX_SCALAR_LENGTH": 5},
                "string",
            ),
        )
        for payload, limits, message in cases:
            with self.subTest(message=message), override_settings(**limits):
                with self.assertRaisesRegex(ValueError, message):
                    inspect_uploaded_file(
                        self._upload(
                            "hostile.json",
                            json.dumps(payload).encode(),
                            "application/json",
                        )
                    )

    def test_csv_column_field_and_jsonl_line_limits(self):
        with override_settings(THREATBRIDGE_MAX_CSV_COLUMNS=2):
            with self.assertRaisesRegex(ValueError, "column limit"):
                inspect_uploaded_file(
                    self._upload("wide.csv", b"a,b,c\n1,2,3\n", "text/csv")
                )
        with override_settings(THREATBRIDGE_MAX_CSV_FIELD_LENGTH=5):
            with self.assertRaisesRegex(ValueError, "field"):
                inspect_uploaded_file(
                    self._upload("field.csv", b"id,name\n1,123456\n", "text/csv")
                )
        with override_settings(THREATBRIDGE_MAX_JSONL_LINE_BYTES=20):
            with self.assertRaisesRegex(ValueError, "line limit"):
                inspect_uploaded_file(
                    self._upload(
                        "line.jsonl",
                        json.dumps({"name": "x" * 30}).encode(),
                        "application/x-ndjson",
                    )
                )

    def test_preview_is_bounded(self):
        payload = [{"device_id": str(index)} for index in range(4)]
        inspection = inspect_uploaded_file(
            self._upload("assets.json", json.dumps(payload).encode(), "application/json")
        )
        self.assertEqual(inspection.record_count, 4)
        self.assertEqual(len(inspection.sample_records), 2)

    def test_rejects_null_archives_encoding_paths_and_content_type_mismatch(self):
        cases = (
            ("null.json", b'{"name":"bad\x00value"}', "application/json", "null byte"),
            ("archive.json", b"PK\x03\x04payload", "application/json", "Archive"),
            ("encoding.json", b"{\xff}", "application/json", "UTF-8"),
            ("data.json", b'[{"device_id":"1"}]', "application/zip", "content type"),
        )
        for name, content, content_type, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, message):
                    inspect_uploaded_file(self._upload(name, content, content_type))

        for name in ("../records.json", "folder/records.json", "folder\\records.json"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "must not contain a path"):
                    _format_from_name(name)

    def test_detected_structure_must_match_selected_type(self):
        payload = [{"device_id": "asset-1", "device_name": "server.example.invalid"}]
        with self.assertRaisesRegex(ValueError, "conflicts"):
            inspect_uploaded_file(
                self._upload("assets.json", json.dumps(payload).encode(), "application/json"),
                object_type="vulnerability",
            )

    def test_normalization_error_retention_is_bounded(self):
        upload = self._upload(
            "assets.csv",
            b"device_id,device_name\n,one\n,two\n,three\n,four\n",
            "text/csv",
        )
        result = create_file_import(
            uploaded_file=upload,
            object_type="asset",
            id_fields=["device_id"],
            origin="management:test_import_limits",
            system=True,
        )
        self.assertEqual(result.run.records_rejected, 4)
        self.assertEqual(result.run.record_errors.count(), 2)

    def test_rejected_stored_upload_is_removed(self):
        upload = self._upload(
            "assets.csv",
            b"device_id,device_name\nasset-1,server.example.invalid\n",
            "text/csv",
        )
        with patch(
            "integrations.file_imports.Integration.objects.create",
            side_effect=RuntimeError,
        ):
            with self.assertRaises(RuntimeError):
                create_file_import(
                    uploaded_file=upload,
                    object_type="auto",
                    origin="management:test_rejected_upload",
                    system=True,
                )
        files = [path for path in Path(self.temporary_directory.name).rglob("*") if path.is_file()]
        self.assertEqual(files, [])
