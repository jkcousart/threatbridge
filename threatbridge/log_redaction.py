from __future__ import annotations

import logging
import re

REDACTED = "<redacted>"

_SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-opencti-token",
)
_SENSITIVE_PARAMETER_HINTS = (
    "access[_-]?key",
    "api[_-]?key",
    "apikey",
    "auth",
    "credential",
    "passwd",
    "password",
    "pwd",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
)

_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)(?:[^/\s:@]+)(?::[^/\s@]*)?@")
# A header value runs to the next parameter separator or end of line, so consume the
# whole thing. Stopping at the first space would leave "Bearer <token>" partly intact.
_HEADER_VALUE = re.compile(
    r"(?i)\b(" + "|".join(_SENSITIVE_HEADERS) + r")(\s*[:=]\s*)"
    r"""(?:"[^"]*"|'[^']*'|[^;,\r\n]*)"""
)
_AUTHENTICATION_SCHEME = re.compile(r"(?i)\b(bearer|basic|token|apikey)\s+[A-Za-z0-9._~+/=\-]{8,}")
_QUERY_PARAMETER = re.compile(
    r"(?i)([?&][^?&=\s\"']*(?:" + "|".join(_SENSITIVE_PARAMETER_HINTS) + r")"
    r"[^?&=\s\"']*=)[^&\s\"']*"
)


def redact(message: str) -> str:
    """Remove credential-bearing substrings from a log line."""

    redacted = _URL_CREDENTIALS.sub(rf"\1{REDACTED}:{REDACTED}@", message)
    # Scheme-prefixed credentials are handled before the header rule so a bare
    # "Bearer <token>" is covered even when no header name precedes it.
    redacted = _AUTHENTICATION_SCHEME.sub(rf"\1 {REDACTED}", redacted)
    redacted = _HEADER_VALUE.sub(rf"\1\2{REDACTED}", redacted)
    return _QUERY_PARAMETER.sub(rf"\1{REDACTED}", redacted)


class SensitiveDataFilter(logging.Filter):
    """Redact credentials from log records before a handler emits them.

    Attach this to handlers rather than loggers so that records propagated from
    child loggers (including Gunicorn access logs) are also covered.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True
