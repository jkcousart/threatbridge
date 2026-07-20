from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase

from threatbridge import settings as threatbridge_settings
from threatbridge.startup_audit import record_production_configuration_failure
from threatbridge.urls import readyz


class SecretKeySettingsTests(SimpleTestCase):
    def test_startup_configuration_event_contains_no_setting_value(self):
        with self.assertLogs("threatbridge.security", level="CRITICAL") as captured:
            record_production_configuration_failure("DJANGO_SECRET_KEY")

        event = captured.output[0]
        self.assertIn("production_configuration.failed", event)
        self.assertIn("DJANGO_SECRET_KEY", event)
        self.assertNotIn("synthetic-production-secret", event)

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
        environment.pop("DJANGO_SECRET_KEY_FILE", None)

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


class ProductionSettingsTests(SimpleTestCase):
    @staticmethod
    def _production_environment() -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "DJANGO_DEBUG": "false",
                "DJANGO_SECRET_KEY": "synthetic-production-secret-" * 4,
                "DJANGO_ALLOWED_HOSTS": "threatbridge.example.invalid",
                "DJANGO_CSRF_TRUSTED_ORIGINS": "https://threatbridge.example.invalid",
                "DJANGO_SECURE_HSTS_SECONDS": "31536000",
                "DATABASE_URL": (
                    "postgresql://threatbridge@database.example.invalid/threatbridge"
                ),
                "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS": "opencti.example.invalid",
                "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS": "10.20.0.0/16",
            }
        )
        environment.pop("DJANGO_TRUST_X_FORWARDED_PROTO", None)
        environment.pop("DJANGO_SECRET_KEY_FILE", None)
        environment.pop("DATABASE_URL_FILE", None)
        return environment

    def _import_settings(self, environment: dict[str, str], expression: str = ""):
        script = "import threatbridge.settings as settings"
        if expression:
            script += f"; print({expression})"
        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=threatbridge_settings.BASE_DIR,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_complete_synthetic_production_configuration_loads(self):
        result = self._import_settings(self._production_environment())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_configuration_requirements_fail_closed(self):
        cases = (
            (
                "DJANGO_ALLOWED_HOSTS",
                "DJANGO_ALLOWED_HOSTS must be explicitly configured",
            ),
            (
                "DJANGO_CSRF_TRUSTED_ORIGINS",
                "DJANGO_CSRF_TRUSTED_ORIGINS must contain explicit HTTPS origins",
            ),
            ("DATABASE_URL", "DATABASE_URL must explicitly select PostgreSQL"),
            (
                "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS",
                "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS must contain exact hostnames",
            ),
            (
                "DJANGO_SECURE_HSTS_SECONDS",
                "DJANGO_SECURE_HSTS_SECONDS must be explicitly configured",
            ),
        )
        for variable, expected in cases:
            with self.subTest(variable=variable):
                environment = self._production_environment()
                environment.pop(variable)
                result = self._import_settings(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_file_backed_production_secrets_load(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            secret_path = directory / "django-secret-key"
            database_path = directory / "database-url"
            secret_path.write_text("file-backed-secret-" * 4, encoding="utf-8")
            database_path.write_text(
                "postgresql://threatbridge@database.example.invalid/threatbridge\n",
                encoding="utf-8",
            )
            secret_path.chmod(0o400)
            database_path.chmod(0o400)

            environment = self._production_environment()
            environment.pop("DJANGO_SECRET_KEY")
            environment.pop("DATABASE_URL")
            environment["DJANGO_SECRET_KEY_FILE"] = str(secret_path)
            environment["DATABASE_URL_FILE"] = str(database_path)
            result = self._import_settings(environment)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_direct_and_file_backed_values_are_mutually_exclusive(self):
        with TemporaryDirectory() as temporary_directory:
            secret_path = Path(temporary_directory) / "django-secret-key"
            secret_path.write_text("duplicate-secret", encoding="utf-8")
            secret_path.chmod(0o400)
            environment = self._production_environment()
            environment["DJANGO_SECRET_KEY_FILE"] = str(secret_path)
            result = self._import_settings(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Set only one of DJANGO_SECRET_KEY or DJANGO_SECRET_KEY_FILE",
                result.stderr,
            )

    def test_file_backed_values_reject_relative_symlink_and_writable_files(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            good = directory / "good"
            good.write_text("value", encoding="utf-8")
            good.chmod(0o400)
            symlink = directory / "link"
            symlink.symlink_to(good)
            writable = directory / "writable"
            writable.write_text("value", encoding="utf-8")
            writable.chmod(0o622)

            for value, expected in (
                ("relative-secret", "absolute path"),
                (str(symlink), "must not be a symlink"),
                (str(writable), "must not be group- or world-writable"),
            ):
                with self.subTest(value=value):
                    environment = self._production_environment()
                    environment.pop("DJANGO_SECRET_KEY")
                    environment["DJANGO_SECRET_KEY_FILE"] = value
                    result = self._import_settings(environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stderr)

    def test_extra_ca_file_must_be_restricted_regular_file(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            ca_file = directory / "internal-root-ca.crt"
            ca_file.write_text("synthetic-ca", encoding="utf-8")
            ca_file.chmod(0o444)
            environment = self._production_environment()
            environment["THREATBRIDGE_EXTRA_CA_FILE"] = str(ca_file)
            result = self._import_settings(
                environment,
                "settings.THREATBRIDGE_EXTRA_CA_FILE",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(ca_file))

            ca_file.chmod(0o666)
            result = self._import_settings(environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not be group- or world-writable", result.stderr)

    def test_wildcard_hosts_and_sqlite_are_rejected(self):
        environment = self._production_environment()
        environment["DJANGO_ALLOWED_HOSTS"] = "*"
        result = self._import_settings(environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact, non-wildcard hosts", result.stderr)

        environment = self._production_environment()
        environment["DATABASE_URL"] = "sqlite:///production.sqlite3"
        result = self._import_settings(environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicitly select PostgreSQL", result.stderr)

    def test_malformed_trusted_origins_and_outbound_hosts_are_rejected(self):
        for origin in (
            "http://threatbridge.example.invalid",
            "https://user@threatbridge.example.invalid",
            "https://threatbridge.example.invalid/path",
            "https://*.example.invalid",
        ):
            with self.subTest(origin=origin):
                environment = self._production_environment()
                environment["DJANGO_CSRF_TRUSTED_ORIGINS"] = origin
                result = self._import_settings(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("explicit HTTPS origins", result.stderr)

        for host in ("*", ".example.invalid", "https://opencti.example.invalid", "host:443"):
            with self.subTest(host=host):
                environment = self._production_environment()
                environment["THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS"] = host
                result = self._import_settings(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("exact hostnames or IP literals", result.stderr)

    def test_proxy_header_trust_requires_explicit_opt_in(self):
        environment = self._production_environment()
        result = self._import_settings(
            environment,
            "hasattr(settings, 'SECURE_PROXY_SSL_HEADER')",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "False")

        environment["DJANGO_TRUST_X_FORWARDED_PROTO"] = "true"
        result = self._import_settings(
            environment,
            "settings.SECURE_PROXY_SSL_HEADER",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HTTP_X_FORWARDED_PROTO", result.stdout)

    def test_rest_framework_uses_session_authentication_without_basic(self):
        authentication = threatbridge_settings.REST_FRAMEWORK[
            "DEFAULT_AUTHENTICATION_CLASSES"
        ]
        self.assertEqual(
            authentication,
            ["rest_framework.authentication.SessionAuthentication"],
        )

    def test_readiness_failure_is_generic(self):
        request = RequestFactory().get("/readyz")
        from unittest.mock import patch

        with patch("threatbridge.urls.connection") as connection:
            connection.cursor.side_effect = RuntimeError("secret")
            response = readyz(request)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"secret", response.content)
        self.assertNotIn(b"error", response.content)
