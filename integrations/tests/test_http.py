from __future__ import annotations

import socket
from io import BytesIO
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request

from django.test import SimpleTestCase, override_settings

from integrations.adapters.http_client import HttpClientError
from integrations.adapters.http_client import request_json as adapter_request_json
from integrations.http import IntegrationHttpError
from integrations.http import request_json as integration_request_json
from integrations.http_response import ResponseTooLargeError, read_bounded_response
from integrations.outbound import (
    UnsafeOutboundUrlError,
    _build_tls_context,
    _create_allowed_connection,
    _PinnedHttpsConnection,
    _ValidatedRedirectHandler,
    validate_outbound_url,
)
from integrations.secrets import redacted_result, validate_safe_cursor

ALLOWED_HOST = "opencti.example.invalid"
OTHER_HOST = "other.example.invalid"
PUBLIC_TEST_ADDRESS = "8.8.8.8"
PRIVATE_TEST_ADDRESS = "10.20.1.10"
PRIVATE_TEST_CIDR = "10.20.0.0/16"


def _address_info(address: str, port: int = 443) -> list[tuple]:
    if ":" in address:
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, port, 0, 0),
            )
        ]
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, port),
        )
    ]


class OutboundUrlValidationTests(SimpleTestCase):
    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PUBLIC_TEST_ADDRESS),
    )
    def test_public_allowlisted_hostname_is_accepted(self, _getaddrinfo):
        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_unlisted_public_hostname_is_rejected_before_dns(self, getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "not allowed"):
            validate_outbound_url(f"https://{OTHER_HOST}/data")

        getaddrinfo.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PRIVATE_TEST_ADDRESS),
    )
    def test_private_hostname_requires_private_cidr_permission(self, _getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "private CIDR allow-list"):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PRIVATE_TEST_ADDRESS),
    )
    def test_private_hostname_within_permitted_cidr_is_accepted(self, _getaddrinfo):
        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info("10.21.1.10"),
    )
    def test_private_hostname_outside_permitted_cidr_is_rejected(self, _getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "outside the allowed private CIDRs"):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=(
            _address_info(PUBLIC_TEST_ADDRESS) + _address_info(PRIVATE_TEST_ADDRESS)
        ),
    )
    def test_mixed_public_and_private_dns_answers_are_rejected(self, _getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "mixed public and private"):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=("0.0.0.0/0", "::/0"),
    )
    def test_loopback_is_rejected_even_with_broad_private_cidr(self):
        for address in ("127.0.0.1", "::1"):
            with self.subTest(address=address):
                with patch(
                    "integrations.outbound.socket.getaddrinfo",
                    return_value=_address_info(address),
                ):
                    with self.assertRaisesRegex(UnsafeOutboundUrlError, "prohibited"):
                        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=("0.0.0.0/0", "::/0"),
    )
    def test_link_local_and_metadata_addresses_are_always_rejected(self):
        for address in (
            "169.254.1.10",
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
        ):
            with self.subTest(address=address):
                with patch(
                    "integrations.outbound.socket.getaddrinfo",
                    return_value=_address_info(address),
                ):
                    with self.assertRaisesRegex(UnsafeOutboundUrlError, "prohibited"):
                        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    def test_ipv4_mapped_ipv6_uses_mapped_ipv4_policy(self):
        with patch(
            "integrations.outbound.socket.getaddrinfo",
            return_value=_address_info("::ffff:10.20.1.10"),
        ):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

        with patch(
            "integrations.outbound.socket.getaddrinfo",
            return_value=_address_info("::ffff:127.0.0.1"),
        ):
            with self.assertRaisesRegex(UnsafeOutboundUrlError, "prohibited"):
                validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=("10.20.0.1/16",),
    )
    def test_malformed_private_cidr_configuration_is_rejected(self):
        with self.assertRaisesRegex(
            UnsafeOutboundUrlError,
            "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS contains an invalid CIDR entry",
        ):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(PRIVATE_TEST_ADDRESS,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PRIVATE_TEST_ADDRESS),
    )
    def test_direct_private_ip_literal_requires_exact_host_and_cidr(self, _getaddrinfo):
        validate_outbound_url(f"https://{PRIVATE_TEST_ADDRESS}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch("integrations.outbound.socket.socket")
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_dns_is_revalidated_immediately_before_connect(self, getaddrinfo, socket_factory):
        getaddrinfo.side_effect = [
            _address_info(PUBLIC_TEST_ADDRESS),
            _address_info("10.21.1.10"),
        ]
        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

        with self.assertRaisesRegex(UnsafeOutboundUrlError, "outside the allowed private CIDRs"):
            _create_allowed_connection((ALLOWED_HOST, 443), timeout=5)

        self.assertEqual(getaddrinfo.call_count, 2)
        socket_factory.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(PRIVATE_TEST_CIDR,),
    )
    @patch("integrations.outbound.socket.socket")
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PRIVATE_TEST_ADDRESS),
    )
    def test_connection_uses_only_validated_resolution_address(
        self, _getaddrinfo, socket_factory
    ):
        connection = Mock()
        socket_factory.return_value = connection

        result = _create_allowed_connection((ALLOWED_HOST, 443), timeout=5)

        self.assertIs(result, connection)
        connection.connect.assert_called_once_with((PRIVATE_TEST_ADDRESS, 443))

    @override_settings(THREATBRIDGE_EXTRA_CA_FILE="/run/configs/internal-root-ca.crt")
    @patch("integrations.outbound.ssl.create_default_context")
    def test_tls_context_adds_reviewed_internal_ca(self, create_default_context):
        context = Mock()
        create_default_context.return_value = context

        result = _build_tls_context()

        self.assertIs(result, context)
        context.load_verify_locations.assert_called_once_with(
            cafile="/run/configs/internal-root-ca.crt"
        )

    def test_tls_connection_retains_original_hostname_for_sni(self):
        tls_context = Mock()
        raw_socket = Mock()
        wrapped_socket = Mock()
        tls_context.wrap_socket.return_value = wrapped_socket
        connection = _PinnedHttpsConnection(ALLOWED_HOST, context=tls_context)
        connection._create_connection = Mock(return_value=raw_socket)

        connection.connect()

        tls_context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname=ALLOWED_HOST,
        )
        self.assertIs(connection.sock, wrapped_socket)

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PUBLIC_TEST_ADDRESS),
    )
    def test_same_origin_redirect_is_revalidated_and_allowed(self, getaddrinfo):
        redirected = _ValidatedRedirectHandler().redirect_request(
            Request(f"https://{ALLOWED_HOST}/start"),
            None,
            302,
            "Found",
            {},
            f"https://{ALLOWED_HOST}/next",
        )

        self.assertEqual(redirected.full_url, f"https://{ALLOWED_HOST}/next")
        getaddrinfo.assert_called_once()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_explicit_port_zero_is_rejected_before_dns(self, getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "between 1 and 65535"):
            validate_outbound_url(f"https://{ALLOWED_HOST}:0/")

        getaddrinfo.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_malformed_and_out_of_range_ports_are_rejected(self):
        for port in ("", "-1", "65536", "not-a-port"):
            with self.subTest(port=port):
                with self.assertRaisesRegex(UnsafeOutboundUrlError, "invalid port"):
                    validate_outbound_url(f"https://{ALLOWED_HOST}:{port}/")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_redirect_from_port_zero_to_default_port_is_rejected(self, getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "between 1 and 65535"):
            _ValidatedRedirectHandler().redirect_request(
                Request(f"https://{ALLOWED_HOST}:0/start"),
                None,
                302,
                "Found",
                {},
                f"https://{ALLOWED_HOST}/next",
            )

        getaddrinfo.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PUBLIC_TEST_ADDRESS),
    )
    def test_default_https_port_and_explicit_443_are_same_origin(self, getaddrinfo):
        redirects = (
            (
                f"https://{ALLOWED_HOST}/start",
                f"https://{ALLOWED_HOST}:443/next",
            ),
            (
                f"https://{ALLOWED_HOST}:443/start",
                f"https://{ALLOWED_HOST}/next",
            ),
        )
        for original_url, redirect_url in redirects:
            with self.subTest(original_url=original_url, redirect_url=redirect_url):
                redirected = _ValidatedRedirectHandler().redirect_request(
                    Request(original_url),
                    None,
                    302,
                    "Found",
                    {},
                    redirect_url,
                )
                self.assertEqual(redirected.full_url, redirect_url)

        self.assertEqual(getaddrinfo.call_count, 2)

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch(
        "integrations.outbound.socket.getaddrinfo",
        return_value=_address_info(PUBLIC_TEST_ADDRESS, port=8443),
    )
    def test_matching_non_default_ports_are_same_origin(self, getaddrinfo):
        redirect_url = f"https://{ALLOWED_HOST}:8443/next"
        redirected = _ValidatedRedirectHandler().redirect_request(
            Request(f"https://{ALLOWED_HOST}:8443/start"),
            None,
            302,
            "Found",
            {},
            redirect_url,
        )

        self.assertEqual(redirected.full_url, redirect_url)
        getaddrinfo.assert_called_once_with(
            ALLOWED_HOST,
            8443,
            type=socket.SOCK_STREAM,
        )

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_redirect_changing_non_default_port_is_rejected(self, getaddrinfo):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "Cross-origin"):
            _ValidatedRedirectHandler().redirect_request(
                Request(f"https://{ALLOWED_HOST}:8443/start"),
                None,
                302,
                "Found",
                {},
                f"https://{ALLOWED_HOST}:9443/next",
            )

        getaddrinfo.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST, OTHER_HOST),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    @patch("integrations.outbound.socket.getaddrinfo")
    def test_cross_origin_redirect_is_rejected_before_dns(self, getaddrinfo):
        redirect_urls = (
            f"https://{OTHER_HOST}/next",
            f"http://{ALLOWED_HOST}/next",
            f"https://{ALLOWED_HOST}:444/next",
        )
        for redirect_url in redirect_urls:
            with self.subTest(redirect_url=redirect_url):
                with self.assertRaisesRegex(UnsafeOutboundUrlError, "Cross-origin"):
                    _ValidatedRedirectHandler().redirect_request(
                        Request(f"https://{ALLOWED_HOST}/start"),
                        None,
                        302,
                        "Found",
                        {},
                        redirect_url,
                    )

        getaddrinfo.assert_not_called()

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_http_is_rejected_in_production(self):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "Plain HTTP"):
            validate_outbound_url(f"http://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_production_requires_an_explicit_host_allow_list(self):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "explicit allow-list"):
            validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_url_credentials_are_rejected(self):
        with self.assertRaisesRegex(UnsafeOutboundUrlError, "username or password"):
            validate_outbound_url(f"https://user:password@{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=True,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_non_http_schemes_are_rejected(self):
        for url in (
            "file:///etc/passwd",
            "data:text/plain,secret",
            "ftp://files.example.invalid/data",
        ):
            with self.subTest(url=url):
                with self.assertRaisesRegex(UnsafeOutboundUrlError, "HTTP or HTTPS"):
                    validate_outbound_url(url)

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=("0.0.0.0/0",),
    )
    def test_unspecified_multicast_reserved_and_documentation_addresses_are_rejected(self):
        for address in ("0.0.0.0", "224.0.0.1", "240.0.0.1", "192.0.2.10"):
            with self.subTest(address=address):
                with patch(
                    "integrations.outbound.socket.getaddrinfo",
                    return_value=_address_info(address),
                ):
                    with self.assertRaises(UnsafeOutboundUrlError):
                        validate_outbound_url(f"https://{ALLOWED_HOST}/data")

    @override_settings(
        DEBUG=False,
        THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=(ALLOWED_HOST,),
        THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=(),
    )
    def test_both_http_helpers_apply_shared_validation(self):
        with self.assertRaises(IntegrationHttpError):
            integration_request_json("file:///etc/passwd")
        with self.assertRaises(HttpClientError):
            adapter_request_json("file:///etc/passwd", retries=0)


class BoundedHttpResponseTests(SimpleTestCase):
    @override_settings(THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES=4)
    def test_content_length_rejects_before_reading(self):
        response = Mock()
        response.headers = {"Content-Length": "5"}
        with self.assertRaises(ResponseTooLargeError):
            read_bounded_response(response)
        response.read.assert_not_called()

    @override_settings(THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES=4)
    def test_streamed_body_is_bounded(self):
        response = Mock()
        response.headers = {}
        response.read.return_value = b"12345"
        with self.assertRaises(ResponseTooLargeError):
            read_bounded_response(response)
        response.read.assert_called_once_with(5)

    @patch("integrations.http.open_outbound_request")
    def test_http_error_omits_query_secrets_and_response_body(self, opener):
        url = f"https://{ALLOWED_HOST}/data?access_token=do-not-store"
        opener.side_effect = HTTPError(
            url,
            400,
            "Bad request",
            {},
            BytesIO(b'{"message":"token do-not-store"}'),
        )
        with self.assertRaises(IntegrationHttpError) as raised:
            integration_request_json(url)
        message = str(raised.exception)
        self.assertNotIn("access_token", message)
        self.assertNotIn("do-not-store", message)
        self.assertIn("HTTP 400", message)

    def test_connector_result_redacts_resolved_secret_values_in_safe_fields(self):
        result = redacted_result(
            {
                "ok": True,
                "detail": "Connected using do-not-display-this-value",
                "nested": {"status": "do-not-display-this-value"},
            },
            resolved_secrets={"value": "do-not-display-this-value"},
        )

        self.assertEqual(result["detail"], "<redacted>")
        self.assertEqual(result["nested"]["status"], "<redacted>")

    def test_connector_cursor_rejects_credentials_but_allows_continuation_tokens(self):
        validate_safe_cursor(
            {"next_url": f"https://{ALLOWED_HOST}/items?$skiptoken=opaque"}
        )

        unsafe_cursors = (
            {"access_token": "dynamic-token"},
            {"next_url": f"https://{ALLOWED_HOST}/items?access_token=dynamic-token"},
            {"after": "prefix-known-secret-suffix"},
        )
        for cursor in unsafe_cursors:
            with self.subTest(cursor=cursor):
                with self.assertRaisesRegex(ValueError, "sensitive material"):
                    validate_safe_cursor(
                        cursor,
                        resolved_secrets={"value": "known-secret"},
                    )
