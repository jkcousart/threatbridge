from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import ParseResult, urlparse
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from django.conf import settings


class UnsafeOutboundUrlError(ValueError):
    pass


_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


def _normalized_hostname(hostname: str) -> str:
    candidate = hostname.strip().rstrip(".")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        pass
    try:
        return candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeOutboundUrlError("Outbound URL contains an invalid hostname") from exc


def _configured_values(setting_name: str) -> tuple[str, ...]:
    configured = getattr(settings, setting_name, ())
    if isinstance(configured, str):
        configured = configured.split(",")
    return tuple(str(value).strip() for value in configured if str(value).strip())


def _allowed_hosts() -> set[str]:
    return {
        _normalized_hostname(host)
        for host in _configured_values("THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS")
    }


def _allowed_private_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for value in _configured_values("THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS"):
        try:
            networks.append(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise UnsafeOutboundUrlError(
                "THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS contains an invalid CIDR entry"
            ) from exc
    return tuple(networks)


def _require_allowed_host(hostname: str) -> str:
    normalized_hostname = _normalized_hostname(hostname)
    allowed_hosts = _allowed_hosts()
    if not settings.DEBUG and not allowed_hosts:
        raise UnsafeOutboundUrlError("Production outbound hosts require an explicit allow-list")
    if normalized_hostname not in allowed_hosts:
        raise UnsafeOutboundUrlError(f"Outbound host is not allowed: {normalized_hostname}")
    return normalized_hostname


def _policy_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address):
    return getattr(address, "ipv4_mapped", None) or address


def _is_prohibited_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or getattr(address, "is_site_local", False)
        or address in _METADATA_ADDRESSES
        or any(
            address.version == network.version and address in network
            for network in _DOCUMENTATION_NETWORKS
        )
    )


def _is_in_allowed_private_network(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(
        address.version == network.version and address in network for network in networks
    )


def _resolved_allowed_addresses(hostname: str, port: int) -> list[tuple]:
    private_networks = _allowed_private_networks()
    normalized_hostname = _require_allowed_host(hostname)
    try:
        addresses = socket.getaddrinfo(normalized_hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeOutboundUrlError(
            f"Outbound host could not be resolved: {normalized_hostname}"
        ) from exc
    if not addresses:
        raise UnsafeOutboundUrlError(
            f"Outbound host could not be resolved: {normalized_hostname}"
        )

    policy_addresses = []
    for _family, _socktype, _proto, _canonname, sockaddr in addresses:
        try:
            address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError as exc:
            raise UnsafeOutboundUrlError(
                f"Outbound host resolved to an invalid address: {normalized_hostname}"
            ) from exc
        policy_address = _policy_address(address)
        if _is_prohibited_address(policy_address):
            raise UnsafeOutboundUrlError(
                f"Outbound host resolves to a prohibited address: {normalized_hostname}"
            )
        policy_addresses.append(policy_address)

    if all(address.is_global for address in policy_addresses):
        return addresses
    if any(address.is_global for address in policy_addresses):
        raise UnsafeOutboundUrlError(
            f"Outbound host has mixed public and private DNS answers: {normalized_hostname}"
        )
    if not private_networks:
        raise UnsafeOutboundUrlError(
            "Private outbound destinations require an explicit private CIDR allow-list"
        )
    if not all(
        _is_in_allowed_private_network(address, private_networks)
        for address in policy_addresses
    ):
        raise UnsafeOutboundUrlError(
            f"Outbound host resolves outside the allowed private CIDRs: {normalized_hostname}"
        )
    return addresses


def _validated_explicit_port(parsed: ParseResult, *, subject: str) -> int | None:
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsafeOutboundUrlError(f"{subject} contains an invalid port") from exc
    authority = parsed.netloc.rsplit("@", 1)[-1]
    if port is None and authority.endswith(":"):
        raise UnsafeOutboundUrlError(f"{subject} contains an invalid port")
    if port == 0:
        raise UnsafeOutboundUrlError(f"{subject} port must be between 1 and 65535")
    return port


def validate_outbound_url(url: str) -> None:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
    except ValueError as exc:
        raise UnsafeOutboundUrlError("Outbound URL is malformed") from exc
    port = _validated_explicit_port(parsed, subject="Outbound URL")

    if parsed.scheme not in {"https", "http"} or not hostname:
        raise UnsafeOutboundUrlError("Outbound URLs must use HTTP or HTTPS")
    if parsed.scheme != "https" and not settings.DEBUG:
        raise UnsafeOutboundUrlError("Plain HTTP integrations are disabled in production")
    if username is not None or password is not None:
        raise UnsafeOutboundUrlError("Outbound URLs must not contain a username or password")

    normalized_hostname = _normalized_hostname(hostname)
    if normalized_hostname == "localhost" or normalized_hostname.endswith(".localhost"):
        raise UnsafeOutboundUrlError("Outbound URLs must not target localhost")

    resolved_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    _resolved_allowed_addresses(normalized_hostname, resolved_port)


def _url_origin(url: str) -> tuple[str, str, int]:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError as exc:
        raise UnsafeOutboundUrlError("Outbound redirect URL is malformed") from exc
    port = _validated_explicit_port(parsed, subject="Outbound redirect URL")
    if parsed.scheme not in {"https", "http"} or not hostname:
        raise UnsafeOutboundUrlError("Outbound redirect URL must use HTTP or HTTPS")
    hostname = _normalized_hostname(hostname)
    port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, hostname, port


def _create_allowed_connection(
    address: tuple[str, int],
    timeout: object = socket._GLOBAL_DEFAULT_TIMEOUT,
    source_address: tuple[str, int] | None = None,
):
    hostname, port = address
    addresses = _resolved_allowed_addresses(hostname, port)
    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in addresses:
        connection = socket.socket(family, socktype, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connection.settimeout(timeout)
            if source_address:
                connection.bind(source_address)
            connection.connect(sockaddr)
            return connection
        except OSError as exc:
            last_error = exc
            connection.close()
    if last_error is not None:
        raise last_error
    raise OSError(f"No usable allowed address for {hostname}")


class _PinnedHttpConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _create_allowed_connection


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _create_allowed_connection




def _build_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    extra_ca_file = getattr(settings, "THREATBRIDGE_EXTRA_CA_FILE", None)
    if extra_ca_file:
        context.load_verify_locations(cafile=extra_ca_file)
    return context


class _PinnedHttpHandler(HTTPHandler):
    def http_open(self, request):
        return self.do_open(_PinnedHttpConnection, request)


class _PinnedHttpsHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(_PinnedHttpsConnection, request, context=self._context)


class _ValidatedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        if _url_origin(request.full_url) != _url_origin(new_url):
            raise UnsafeOutboundUrlError("Cross-origin outbound redirects are not allowed")
        validate_outbound_url(new_url)
        return super().redirect_request(request, fp, code, message, headers, new_url)


def open_outbound_request(request: Request, *, timeout: int):
    validate_outbound_url(request.full_url)
    opener = build_opener(
        ProxyHandler({}),
        _PinnedHttpHandler(),
        _PinnedHttpsHandler(context=_build_tls_context()),
        _ValidatedRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)
