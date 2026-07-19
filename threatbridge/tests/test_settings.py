from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from threatbridge import settings as threatbridge_settings


class SecretKeySettingsTests(SimpleTestCase):
    def test_development_secret_is_persistent_and_restrictively_permissioned(self):
        with TemporaryDirectory() as temporary_directory:
            secret_path = Path(temporary_directory) / ".secrets" / "django-secret-key"

            first_secret = threatbridge_settings._secret_key(
                debug=True,
                configured_secret=None,
                local_path=secret_path,
            )
            second_secret = threatbridge_settings._secret_key(
                debug=True,
                configured_secret=None,
                local_path=secret_path,
            )

            self.assertEqual(first_secret, second_secret)
            self.assertGreaterEqual(len(first_secret), 64)
            self.assertEqual(stat.S_IMODE(secret_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(secret_path.parent.stat().st_mode), 0o700)

    def test_production_helper_fails_closed_without_configured_secret(self):
        with TemporaryDirectory() as temporary_directory:
            with self.assertRaisesRegex(ImproperlyConfigured, "DJANGO_SECRET_KEY must be set"):
                threatbridge_settings._secret_key(
                    debug=False,
                    configured_secret=None,
                    local_path=Path(temporary_directory) / "unused",
                )

    def test_production_settings_import_fails_without_environment_secret(self):
        environment = os.environ.copy()
        environment["DJANGO_DEBUG"] = "false"
        environment.pop("DJANGO_SECRET_KEY", None)

        result = subprocess.run(
            [sys.executable, "-c", "import threatbridge.settings"],
            cwd=threatbridge_settings.BASE_DIR,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY must be set", result.stderr)
