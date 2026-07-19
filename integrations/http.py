from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request

from .http_response import ResponseTooLargeError, read_bounded_response
from .outbound import UnsafeOutboundUrlError, open_outbound_request


@dataclass
class IntegrationHttpError(RuntimeError):
    status: int | None
    message: str
    url: str

    def __str__(self) -> str:
        prefix = f"HTTP {self.status}" if self.status else "HTTP request failed"
        return f"{prefix}: {self.message} ({self.url})"


def _safe_url(url: str) -> str:
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    port = f":{parsed_port}" if parsed_port else ""
    return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path, "", ""))


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    json_body: Mapping[str, Any] | None = None,
    form_body: Mapping[str, Any] | None = None,
    timeout: int = 30,
) -> Mapping[str, Any]:
    request_headers = {"Accept": "application/json", **dict(headers or {})}
    body: bytes | None = None
    if json_body is not None and form_body is not None:
        raise ValueError("Choose either json_body or form_body")
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif form_body is not None:
        body = urlencode({key: str(value) for key, value in form_body.items()}).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    try:
        request = Request(url=url, data=body, method=method, headers=request_headers)
        with open_outbound_request(request, timeout=timeout) as response:
            payload = read_bounded_response(response)
    except UnsafeOutboundUrlError as exc:
        raise IntegrationHttpError(None, str(exc), _safe_url(url)) from exc
    except HTTPError as exc:
        raise IntegrationHttpError(
            exc.code,
            "Remote endpoint returned an error",
            _safe_url(url),
        ) from exc
    except URLError as exc:
        raise IntegrationHttpError(
            None,
            f"Network failure ({type(exc.reason).__name__})",
            _safe_url(url),
        ) from exc
    except ResponseTooLargeError as exc:
        raise IntegrationHttpError(None, str(exc), _safe_url(url)) from exc

    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationHttpError(None, "Response was not valid JSON", _safe_url(url)) from exc
    if not isinstance(decoded, dict):
        raise IntegrationHttpError(None, "Expected a JSON object response", _safe_url(url))
    return decoded
