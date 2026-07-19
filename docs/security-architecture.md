# Security architecture

## Trust boundaries

ThreatBridge accepts authenticated browser/API requests, local file imports, and read-only connector
responses. Django sessions and CSRF protect interactive mutations. Named permissions protect every
workflow mutation; staff status is not an application role.

Connector destinations pass centralized HTTPS, exact-host, DNS, address-range, redirect, proxy, and
connection-pinning validation. Private destinations require both an exact host entry and an allowed
private CIDR. DNS is revalidated immediately before connection, and TLS SNI/certificate validation
uses the original hostname.

HTTP response bodies are limited by `THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES`. Connector failures are
stored and displayed as bounded type/status summaries without query strings, headers, bodies,
credentials, or resolved secret values.

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

Malware scanning and quarantine are not implemented. A production deployment must provide both
before accepting untrusted uploads.

## Deferred architecture

Tenant isolation, organization scoping, enterprise SSO, full TLP enforcement, automatic policy
decisions, connector write-back, and automatic blocking/remediation are explicitly outside Phase 1.
