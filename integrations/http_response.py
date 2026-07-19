from __future__ import annotations

from typing import Any

from django.conf import settings


class ResponseTooLargeError(ValueError):
    pass


def maximum_response_bytes() -> int:
    maximum = int(getattr(settings, "THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES", 10 * 1024 * 1024))
    if maximum < 1:
        raise ValueError("THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES must be positive")
    return maximum


def read_bounded_response(response: Any) -> bytes:
    maximum = maximum_response_bytes()
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            declared = int(content_length)
        except (TypeError, ValueError):
            declared = 0
        if declared > maximum:
            raise ResponseTooLargeError(
                f"Integration response exceeds the configured {maximum:,}-byte limit"
            )

    payload = response.read(maximum + 1)
    if len(payload) > maximum:
        raise ResponseTooLargeError(
            f"Integration response exceeds the configured {maximum:,}-byte limit"
        )
    return payload
