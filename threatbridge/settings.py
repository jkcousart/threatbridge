from __future__ import annotations

import os
import secrets
from ipaddress import ip_address, ip_network
from pathlib import Path
from urllib.parse import urlsplit

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

from threatbridge.startup_audit import record_production_configuration_failure

BASE_DIR = Path(__file__).resolve().parent.parent


def _environment_boolean(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise ImproperlyConfigured(f"{name} must be true or false")
    return normalized == "true"


DEBUG = _environment_boolean("DJANGO_DEBUG", True)


def _development_secret(path: Path) -> str:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    try:
        secret = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        secret = secrets.token_urlsafe(64)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            secret = path.read_text(encoding="utf-8").strip()
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8") as secret_file:
                secret_file.write(secret)
                secret_file.write("\n")
    if not secret:
        raise ImproperlyConfigured(f"Development secret file is empty: {path}")
    path.chmod(0o600)
    return secret


def _secret_key(*, debug: bool, configured_secret: str | None, local_path: Path) -> str:
    if configured_secret:
        return configured_secret
    if not debug:
        record_production_configuration_failure("DJANGO_SECRET_KEY")
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG=false")
    return _development_secret(local_path)


SECRET_KEY = _secret_key(
    debug=DEBUG,
    configured_secret=os.getenv("DJANGO_SECRET_KEY"),
    local_path=BASE_DIR / ".secrets" / "django-secret-key",
)

ALLOWED_HOSTS = [
    value.strip()
    for value in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if value.strip()
]
CSRF_TRUSTED_ORIGINS = [
    value.strip()
    for value in os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",")
    if value.strip()
]

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}")


def _is_exact_https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and (port is None or port > 0)
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and "*" not in value
    )


def _is_exact_outbound_host(value: str) -> bool:
    candidate = value.strip().rstrip(".")
    if (
        not candidate
        or "*" in candidate
        or candidate.startswith(".")
        or any(character.isspace() for character in candidate)
        or any(character in candidate for character in "/@")
    ):
        return False
    literal = (
        candidate[1:-1]
        if candidate.startswith("[") and candidate.endswith("]")
        else candidate
    )
    try:
        ip_address(literal)
        return True
    except ValueError:
        pass
    if ":" in candidate:
        return False
    try:
        ascii_hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return all(label and len(label) <= 63 for label in ascii_hostname.split("."))


def _validate_production_configuration() -> None:
    if DEBUG:
        return
    configured_hosts = os.getenv("DJANGO_ALLOWED_HOSTS")
    if not configured_hosts or not ALLOWED_HOSTS:
        record_production_configuration_failure("DJANGO_ALLOWED_HOSTS")
        raise ImproperlyConfigured(
            "DJANGO_ALLOWED_HOSTS must be explicitly configured when DJANGO_DEBUG=false"
        )
    if any("*" in host or host.startswith(".") for host in ALLOWED_HOSTS):
        record_production_configuration_failure("DJANGO_ALLOWED_HOSTS")
        raise ImproperlyConfigured(
            "DJANGO_ALLOWED_HOSTS must contain exact, non-wildcard hosts in production"
        )
    if not CSRF_TRUSTED_ORIGINS or not all(
        _is_exact_https_origin(origin) for origin in CSRF_TRUSTED_ORIGINS
    ):
        record_production_configuration_failure("DJANGO_CSRF_TRUSTED_ORIGINS")
        raise ImproperlyConfigured(
            "DJANGO_CSRF_TRUSTED_ORIGINS must contain explicit HTTPS origins in production"
        )
    configured_database = os.getenv("DATABASE_URL")
    database_url = urlsplit(configured_database or "")
    if (
        not configured_database
        or database_url.scheme not in {"postgres", "postgresql"}
        or not database_url.hostname
    ):
        record_production_configuration_failure("DATABASE_URL")
        raise ImproperlyConfigured(
            "DATABASE_URL must explicitly select PostgreSQL when DJANGO_DEBUG=false"
        )
    configured_outbound_hosts = [
        value.strip()
        for value in os.getenv("THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS", "").split(",")
        if value.strip()
    ]
    if not configured_outbound_hosts or not all(
        _is_exact_outbound_host(host) for host in configured_outbound_hosts
    ):
        record_production_configuration_failure("THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS")
        raise ImproperlyConfigured(
            "THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS must contain exact hostnames or "
            "IP literals in production"
        )
    hsts_value = os.getenv("DJANGO_SECURE_HSTS_SECONDS")
    if hsts_value is None:
        record_production_configuration_failure("DJANGO_SECURE_HSTS_SECONDS")
        raise ImproperlyConfigured(
            "DJANGO_SECURE_HSTS_SECONDS must be explicitly configured in production"
        )
    try:
        if int(hsts_value) < 0:
            raise ValueError
    except ValueError as exc:
        record_production_configuration_failure("DJANGO_SECURE_HSTS_SECONDS")
        raise ImproperlyConfigured(
            "DJANGO_SECURE_HSTS_SECONDS must be a non-negative integer"
        ) from exc


_validate_production_configuration()

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "integrations",
    "catalog",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "threatbridge.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]
WSGI_APPLICATION = "threatbridge.wsgi.application"
ASGI_APPLICATION = "threatbridge.asgi.application"

DATABASES = {
    "default": dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=60,
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.getenv("DJANGO_TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = Path(os.getenv("DJANGO_STATIC_ROOT", BASE_DIR / "staticfiles"))
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 100,
}

THREATBRIDGE_DATA_DIR = Path(os.getenv("THREATBRIDGE_DATA_DIR", BASE_DIR / "data"))
THREATBRIDGE_ALLOWED_ADAPTER_PREFIXES = tuple(
    value.strip()
    for value in os.getenv(
        "THREATBRIDGE_ALLOWED_ADAPTER_PREFIXES",
        "integrations.adapters.",
    ).split(",")
    if value.strip()
)
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS = tuple(
    value.strip().lower()
    for value in os.getenv("THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS", "").split(",")
    if value.strip()
)
THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS = tuple(
    value.strip()
    for value in os.getenv("THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS", "").split(",")
    if value.strip()
)

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = _environment_boolean(
    "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS",
    False,
)
SECURE_HSTS_PRELOAD = _environment_boolean("DJANGO_SECURE_HSTS_PRELOAD", False)
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    if _environment_boolean("DJANGO_TRUST_X_FORWARDED_PROTO", False):
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

THREATBRIDGE_MAX_PAGES_PER_SYNC = int(
    os.getenv("THREATBRIDGE_MAX_PAGES_PER_SYNC", "50")
)
THREATBRIDGE_MAX_UPLOAD_BYTES = int(
    os.getenv("THREATBRIDGE_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024))
)
THREATBRIDGE_MAX_IMPORT_RECORDS = int(
    os.getenv("THREATBRIDGE_MAX_IMPORT_RECORDS", "100000")
)
THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES = int(
    os.getenv("THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES", str(10 * 1024 * 1024))
)
THREATBRIDGE_MAX_JSON_DEPTH = int(os.getenv("THREATBRIDGE_MAX_JSON_DEPTH", "20"))
THREATBRIDGE_MAX_OBJECT_FIELDS = int(
    os.getenv("THREATBRIDGE_MAX_OBJECT_FIELDS", "500")
)
THREATBRIDGE_MAX_FIELD_NAME_LENGTH = int(
    os.getenv("THREATBRIDGE_MAX_FIELD_NAME_LENGTH", "200")
)
THREATBRIDGE_MAX_SCALAR_LENGTH = int(
    os.getenv("THREATBRIDGE_MAX_SCALAR_LENGTH", "100000")
)
THREATBRIDGE_MAX_CSV_COLUMNS = int(os.getenv("THREATBRIDGE_MAX_CSV_COLUMNS", "500"))
THREATBRIDGE_MAX_CSV_FIELD_LENGTH = int(
    os.getenv("THREATBRIDGE_MAX_CSV_FIELD_LENGTH", "100000")
)
THREATBRIDGE_MAX_JSONL_LINE_BYTES = int(
    os.getenv("THREATBRIDGE_MAX_JSONL_LINE_BYTES", str(1024 * 1024))
)
THREATBRIDGE_MAX_PREVIEW_SAMPLES = int(
    os.getenv("THREATBRIDGE_MAX_PREVIEW_SAMPLES", "5")
)
THREATBRIDGE_MAX_IMPORT_ERRORS = int(
    os.getenv("THREATBRIDGE_MAX_IMPORT_ERRORS", "100")
)

for private_cidr in THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS:
    try:
        ip_network(private_cidr, strict=True)
    except ValueError as exc:
        if not DEBUG:
            record_production_configuration_failure(
                "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS"
            )
        raise ImproperlyConfigured(
            "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS contains an invalid CIDR entry"
        ) from exc
