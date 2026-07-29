# Security architecture

## Trust boundaries

ThreatBridge accepts authenticated browser/API requests, local file imports, and read-only connector
responses. Django sessions and CSRF protect interactive mutations. Named permissions protect every
workflow mutation; staff status is not an application role.

Interactive and API surfaces are rate limited in production. Django REST Framework applies an
anonymous and an authenticated throttle (`THREATBRIDGE_ANON_THROTTLE_RATE`,
`THREATBRIDGE_USER_THROTTLE_RATE`). Every logging handler applies
`threatbridge.log_redaction.SensitiveDataFilter`, so `Authorization`, `Cookie`, and API-key headers,
`Bearer`/`Basic`/`Token` credentials, URL userinfo, and sensitive query parameters are removed from
application and Gunicorn access logs alike.

## Outbound connector and SSRF model

ThreatBridge makes outbound requests only through `integrations.outbound.open_outbound_request`,
which is built on Python's `urllib` with a pinned connection factory. There is no proxy support, no
shell execution, and no path that skips validation. The policy is deny-by-default and is applied
twice: once when the URL is validated, and again inside the socket factory immediately before
`connect()`, which is what defeats DNS rebinding.

A destination is reachable only if all of the following hold.

- The scheme is `http` or `https`. In production plain `http` is rejected outright, so remote
  connectors are HTTPS by default.
- The URL carries no username or password.
- The port, if present, is explicit and valid.
- The hostname appears verbatim in `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS`. Production requires that
  list to be non-empty, so an unconfigured deployment can reach nothing.
- The hostname is not `localhost`, not a `.localhost` subdomain, and not a cloud metadata name
  (`metadata`, `metadata.google.internal`, `metadata.goog`, `metadata.oraclecloud.com`,
  `instance-data`, or a subdomain of any of them). Metadata names are refused even if an
  administrator allowlists them.
- Every address the hostname resolves to passes address policy. Loopback, link-local, multicast,
  unspecified, reserved, site-local, documentation, and known metadata addresses
  (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`) are always refused.
  Tunnelling and translation prefixes that embed an inner IPv4 address are also always refused
  (`192.88.99.0/24`, `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `2001::/32`), because those can
  be globally routable while still terminating on an internal host.
- IPv4 and IPv6 are both handled, and an IPv4-mapped IPv6 answer is evaluated as the IPv4 address it
  contains, so `::ffff:127.0.0.1` is treated as loopback.
- Answers must be consistently public or consistently private. A mixed public/private answer set is
  refused rather than resolved in the attacker's favour.
- A private answer additionally requires every resolved address to fall inside
  `THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS`. Reaching a privately hosted integration therefore
  needs two independent, explicit approvals: the exact host and the covering CIDR.

Redirects are followed at most `MAX_REDIRECTS` (3) times, must stay same-origin, and are re-validated
against the full policy above before being followed. Connections are pinned to a validated address
while TLS SNI and certificate validation continue to use the original hostname, so certificate
verification is never weakened to accommodate pinning. Private trust anchors are added with
`load_verify_locations` through `THREATBRIDGE_EXTRA_CA_FILE`; verification is never disabled.

Requests carry a fixed `User-Agent` of `ThreatBridge/0.3` and `Accept-Encoding: identity`, disclosing
no host, interpreter, or deployment detail and avoiding ambiguity about the size of a bounded read.
Connect and read timeouts are separate: the connect phase is capped by
`THREATBRIDGE_OUTBOUND_CONNECT_TIMEOUT` (default 10 seconds, never above the read timeout), and the
remaining budget applies to reads. Retries are bounded with exponential backoff honouring
`Retry-After`.

HTTP response bodies are limited by `THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES`, enforced against both the
declared `Content-Length` and the actual read, so nothing streams unbounded into memory. Connector
failures are stored and displayed as bounded type/status summaries without query strings, headers,
bodies, credentials, or resolved secret values.

## Evidence and derived data

`ExternalObject` stores the latest raw and normalized record for an integration/type/external-ID
key with a content hash; it is not immutable version history. Derived records are exposed only when
their provenance remains active. Soft-deleted evidence is available only to explicit auditors,
cannot be projected or assessed, and is not automatically resurrected.

ATT&CK mappings begin pending and require an explicit review transition. Mapping history and
security events are append-only through application/admin paths. Audit metadata is bounded and
redacts credential, token, header, cookie, raw-record, upload-content, and unrestricted-exception
fields.

Changes to Django users, groups, or permission assignments require the named security-configuration
permission and emit a security-configuration audit event. Django staff status alone is insufficient.
Fail-closed startup configuration errors use a value-free structured process-log fallback because
the database audit service is not safely available before settings initialization.

New assessments store a complete manifest of the active report, ATT&CK, detection, telemetry,
validation, vulnerability, finding, and asset source records used. Deleting any listed evidence
hides the dependent assessment. Pre-Phase-1 assessments without a provably complete manifest are
hidden until explicitly recalculated.

## File ingestion

CSV, JSON, JSONL, and NDJSON imports enforce byte, record, nesting, object-field, field-name,
scalar, column, CSV-field, JSONL-line, preview, and retained-error limits. Imports reject malformed
encodings, null bytes, compressed/archive signatures, traversal filenames, content-type conflicts,
and selected-type structural conflicts. Server-generated paths remain under the configured data
directory, and rejected stored files are removed.

Django's own request limits are aligned with those application limits:
`DATA_UPLOAD_MAX_MEMORY_SIZE` sits just above `THREATBRIDGE_MAX_UPLOAD_BYTES`, and the number of form
fields and files per request is capped, so an oversized or field-flooded request is rejected by the
framework before import code runs. Stored uploads are written mode `0600` into directories created
mode `0700`. No import path uses `pickle`, `yaml.load`, `eval`, `exec`, or any other unsafe
deserialisation, and ThreatBridge exposes no CSV export, so spreadsheet formula injection is not
reachable.

ThreatBridge is not a malware sandbox. Uploaded files are parsed as data and are never executed,
detonated, unpacked, or emulated. Malware scanning and quarantine are not implemented. A production
deployment must provide both before accepting untrusted uploads.

## Deferred architecture

Tenant isolation, organization scoping, enterprise SSO, full TLP enforcement, automatic policy
decisions, connector write-back, and automatic blocking/remediation are explicitly outside Phase 1.
