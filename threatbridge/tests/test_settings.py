from __future__ import annotations

import hashlib
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase

from threatbridge import settings as threatbridge_settings
from threatbridge.log_redaction import SensitiveDataFilter, redact
from threatbridge.startup_audit import record_production_configuration_failure
from threatbridge.urls import readyz


# Synthetic but deliberately strong: long enough, varied enough, and free of the
# placeholder markers that production configuration validation rejects. Deriving the
# values keeps a high-entropy literal out of the source tree, where a secret scanner can
# only treat it as a candidate credential.
def _strong_test_key(label: str) -> str:
    return "Tb" + hashlib.blake2b(label.encode(), digest_size=32).hexdigest() + "Zq"


STRONG_TEST_SECRET_KEY = _strong_test_key("threatbridge-unit")
SECOND_STRONG_TEST_SECRET_KEY = _strong_test_key("threatbridge-rotation")

# No credential shape of its own; it only has to prove that redaction removes whatever
# sits in a credential position.
REDACTION_FIXTURE_VALUE = "redaction-fixture-value"


class SecretKeySettingsTests(SimpleTestCase):
    def test_startup_configuration_event_contains_no_setting_value(self):
        with self.assertLogs("threatbridge.security", level="CRITICAL") as captured:
            record_production_configuration_failure("DJANGO_SECRET_KEY")

        event = captured.output[0]
        self.assertIn("production_configuration.failed", event)
        self.assertIn("DJANGO_SECRET_KEY", event)
        self.assertNotIn(STRONG_TEST_SECRET_KEY, event)

    def test_weak_and_placeholder_production_secrets_are_rejected(self):
        cases = (
            ("short", "at least 50 characters"),
            (STRONG_TEST_SECRET_KEY, None),
            ("change-me-" * 8, "looks like a placeholder"),
            ("django-insecure-" * 5, "looks like a placeholder"),
            ("replace-this-secret-" * 4, "looks like a placeholder"),
            ("abababababababababababababababababababababababababab", "distinct characters"),
        )
        for secret, expected in cases:
            with self.subTest(secret=secret[:12]):
                if expected is None:
                    threatbridge_settings._validate_secret_key_strength(secret)
                    continue
                with self.assertRaisesRegex(ImproperlyConfigured, expected):
                    threatbridge_settings._validate_secret_key_strength(secret)

    def test_development_secret_is_not_strength_checked(self):
        with TemporaryDirectory() as temporary_directory:
            secret = threatbridge_settings._secret_key(
                debug=True,
                configured_secret="short-development-value",
                local_path=Path(temporary_directory) / "unused",
            )
        self.assertEqual(secret, "short-development-value")

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
                "DJANGO_SECRET_KEY": STRONG_TEST_SECRET_KEY,
                "DJANGO_ALLOWED_HOSTS": "threatbridge.example.invalid",
                "DJANGO_CSRF_TRUSTED_ORIGINS": "https://threatbridge.example.invalid",
                "DJANGO_SECURE_HSTS_SECONDS": "31536000",
                "DATABASE_URL": ("postgresql://threatbridge@database.example.invalid/threatbridge"),
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
            secret_path.write_text(SECOND_STRONG_TEST_SECRET_KEY, encoding="utf-8")
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
        authentication = threatbridge_settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
        self.assertEqual(
            authentication,
            ["rest_framework.authentication.SessionAuthentication"],
        )

    def test_hsts_preload_requires_a_completed_rollout(self):
        cases = (
            (
                {"DJANGO_SECURE_HSTS_PRELOAD": "true"},
                "DJANGO_SECURE_HSTS_PRELOAD requires",
            ),
            (
                {
                    "DJANGO_SECURE_HSTS_PRELOAD": "true",
                    "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS": "true",
                    "DJANGO_SECURE_HSTS_SECONDS": "3600",
                },
                "DJANGO_SECURE_HSTS_PRELOAD requires",
            ),
            (
                {
                    "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS": "true",
                    "DJANGO_SECURE_HSTS_SECONDS": "0",
                },
                "has no effect while",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                environment = self._production_environment()
                environment.update(overrides)
                result = self._import_settings(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_fully_staged_hsts_preload_is_accepted(self):
        environment = self._production_environment()
        environment.update(
            {
                "DJANGO_SECURE_HSTS_SECONDS": "31536000",
                "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS": "true",
                "DJANGO_SECURE_HSTS_PRELOAD": "true",
            }
        )
        result = self._import_settings(environment)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_upload_limits_bound_the_request_body(self):
        self.assertGreater(
            threatbridge_settings.DATA_UPLOAD_MAX_MEMORY_SIZE,
            threatbridge_settings.THREATBRIDGE_MAX_UPLOAD_BYTES,
        )
        self.assertLessEqual(
            threatbridge_settings.FILE_UPLOAD_MAX_MEMORY_SIZE,
            threatbridge_settings.THREATBRIDGE_MAX_UPLOAD_BYTES,
        )
        self.assertEqual(threatbridge_settings.FILE_UPLOAD_PERMISSIONS, 0o600)
        self.assertEqual(threatbridge_settings.FILE_UPLOAD_DIRECTORY_PERMISSIONS, 0o700)
        self.assertGreater(threatbridge_settings.DATA_UPLOAD_MAX_NUMBER_FIELDS, 0)
        self.assertGreater(threatbridge_settings.DATA_UPLOAD_MAX_NUMBER_FILES, 0)

    def test_api_throttling_is_configured_for_anonymous_and_authenticated_callers(self):
        framework = threatbridge_settings.REST_FRAMEWORK
        self.assertEqual(
            framework["DEFAULT_THROTTLE_CLASSES"],
            [
                "rest_framework.throttling.AnonRateThrottle",
                "rest_framework.throttling.UserRateThrottle",
            ],
        )
        rates = framework["DEFAULT_THROTTLE_RATES"]
        self.assertTrue(rates["anon"])
        self.assertTrue(rates["user"])

    def test_forwarded_host_and_port_headers_are_never_trusted(self):
        self.assertFalse(threatbridge_settings.USE_X_FORWARDED_HOST)
        self.assertFalse(threatbridge_settings.USE_X_FORWARDED_PORT)

    def test_every_logging_handler_redacts_sensitive_data(self):
        handlers = threatbridge_settings.LOGGING["handlers"]
        self.assertTrue(handlers)
        for name, handler in handlers.items():
            with self.subTest(handler=name):
                self.assertIn("redact_sensitive_data", handler["filters"])
        for logger_name in ("gunicorn.access", "gunicorn.error"):
            logger = threatbridge_settings.LOGGING["loggers"][logger_name]
            self.assertEqual(logger["handlers"], ["console"])
            self.assertFalse(logger["propagate"])

    def test_readiness_failure_is_generic(self):
        request = RequestFactory().get("/readyz")
        from unittest.mock import patch

        with patch("threatbridge.urls.connection") as connection:
            connection.cursor.side_effect = RuntimeError("secret")
            response = readyz(request)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"secret", response.content)
        self.assertNotIn(b"error", response.content)


class LogRedactionTests(SimpleTestCase):
    def test_credential_bearing_log_lines_are_redacted(self):
        value = REDACTION_FIXTURE_VALUE
        cases = (
            f"Authorization: Bearer {value}",
            f'{{"Authorization": "Token {value}"}}',
            f"Cookie: sessionid={value}",
            f"set-cookie: csrftoken={value}; Path=/",
            f"x-api-key={value}",
            f"GET /api/x?api_token={value} HTTP/1.1",
            f"GET /a?page=2&secret={value}&z=1 HTTP/1.1",
            f"https://operator:{value}@opencti.example.invalid/graphql",
            f"basic {value}",
        )
        for line in cases:
            with self.subTest(line=line):
                redacted = redact(line)
                self.assertNotIn(value, redacted)
                self.assertIn("<redacted>", redacted)

    def test_redaction_preserves_non_sensitive_context(self):
        redacted = redact("GET /api/integrations/?page=2 HTTP/1.1 200 1234")
        self.assertEqual(redacted, "GET /api/integrations/?page=2 HTTP/1.1 200 1234")

    def test_filter_rewrites_the_record_and_keeps_it(self):
        record = logging.LogRecord(
            name="gunicorn.access",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="GET /api/x?token=%s HTTP/1.1",
            args=("abcdef1234567890",),
            exc_info=None,
        )
        self.assertTrue(SensitiveDataFilter().filter(record))
        self.assertNotIn("abcdef1234567890", record.getMessage())
        self.assertIn("<redacted>", record.getMessage())


class RuntimeEntryPointTests(SimpleTestCase):
    def _run_entry_point(self, module: str, environment: dict[str, str]):
        return subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            cwd=threatbridge_settings.BASE_DIR,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_wsgi_and_asgi_refuse_to_start_without_an_explicit_debug_value(self):
        for module in ("threatbridge.wsgi", "threatbridge.asgi"):
            with self.subTest(module=module):
                environment = os.environ.copy()
                environment.pop("DJANGO_DEBUG", None)
                result = self._run_entry_point(module, environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("DJANGO_DEBUG must be set explicitly", result.stderr)
                self.assertIn("production_configuration.failed", result.stderr)

    def test_wsgi_starts_when_debug_is_explicitly_declared(self):
        environment = os.environ.copy()
        environment["DJANGO_DEBUG"] = "true"
        result = self._run_entry_point("threatbridge.wsgi", environment)
        self.assertEqual(result.returncode, 0, result.stderr)
