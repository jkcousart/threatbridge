from __future__ import annotations

import os
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from integrations.secrets import resolve_secret_reference


class SecretFileReferenceTests(SimpleTestCase):
    def _secret_file(self, directory: str, value: str, *, mode: int = 0o600) -> Path:
        path = Path(directory) / "opencti-token"
        path.write_text(value, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_plain_secret_file_is_loaded_without_persisting_its_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._secret_file(directory, "synthetic-opencti-token\n")
            self.assertEqual(
                resolve_secret_reference(f"file:{path}"),
                {"value": "synthetic-opencti-token"},
            )

    def test_json_secret_file_can_name_the_opencti_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._secret_file(
                directory,
                '{"token":"synthetic-opencti-token"}',
            )
            self.assertEqual(
                resolve_secret_reference(f"file:{path}"),
                {"token": "synthetic-opencti-token"},
            )

    def test_secret_file_rejects_group_or_other_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._secret_file(directory, "synthetic-token", mode=0o640)
            with self.assertRaisesRegex(ValueError, "group or other permissions"):
                resolve_secret_reference(f"file:{path}")

    def test_secret_file_requires_an_absolute_non_symlink_path(self):
        with self.assertRaisesRegex(ValueError, "absolute path"):
            resolve_secret_reference("file:relative-token")

        with tempfile.TemporaryDirectory() as directory:
            target = self._secret_file(directory, "synthetic-token")
            link = Path(directory) / "token-link"
            os.symlink(target, link)
            with self.assertRaisesRegex(ValueError, "could not be opened"):
                resolve_secret_reference(f"file:{link}")
