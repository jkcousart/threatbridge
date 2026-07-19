from __future__ import annotations

import os
import secrets
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.getenv("DJANGO_DEBUG", "true").lower() == "true"


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
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
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
        "rest_framework.authentication.BasicAuthentication",
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
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
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
