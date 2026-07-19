from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from integrations.http_response import ResponseTooLargeError, read_bounded_response
from integrations.outbound import UnsafeOutboundUrlError, open_outbound_request


class HttpClientError(RuntimeError):
    pass


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    json_body: Mapping[str, Any] | None = None,
    form_body: Mapping[str, Any] | None = None,
    timeout: int = 30,
    retries: int = 3,
) -> Mapping[str, Any]:
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "ThreatBridge/0.2",
        **dict(headers or {}),
    }
    body: bytes | None = None
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    elif form_body is not None:
        body = urlencode(form_body).encode("utf-8")
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = Request(url, data=body, headers=request_headers, method=method.upper())
        try:
            with open_outbound_request(request, timeout=timeout) as response:
                payload = read_bounded_response(response).decode("utf-8")
                decoded = json.loads(payload) if payload else {}
                if not isinstance(decoded, Mapping):
                    raise HttpClientError("Expected a JSON object response")
                return decoded
        except HTTPError as exc:
            last_error = exc
            if exc.code not in {429, 500, 502, 503, 504} or attempt >= retries:
                raise HttpClientError(f"Remote endpoint returned HTTP {exc.code}") from exc
            retry_after = exc.headers.get("Retry-After")
            delay = float(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
            time.sleep(min(delay, 10))
        except UnsafeOutboundUrlError as exc:
            raise HttpClientError(str(exc)) from exc
        except ResponseTooLargeError as exc:
            raise HttpClientError(str(exc)) from exc
        except (URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt >= retries:
                raise HttpClientError(
                    f"Connector request failed ({type(exc).__name__})"
                ) from exc
            time.sleep(min(2**attempt, 10))
    raise HttpClientError(
        f"Connector request failed ({type(last_error).__name__})"
    )
