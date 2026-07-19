# ThreatBridge integration setup

ThreatBridge integrations are read-only by default. Every connector stores the latest source record
it supplied in `ExternalObject` before projecting normalized values into the canonical catalog.
Credentials are referenced through environment variables and are never stored in the
`Integration.configuration` JSON.

## Create an integration

Sign in through `/accounts/login/`, open `/integrations/`, and select **Add API integration**
to create an integration with an authenticated Django Admin browser session. Staff status permits
admin entry only; integration viewing and configuration require `integrations.view_integration` and
`integrations.configure_integration` respectively.

Test and synchronize a configured integration:

1. Sign in and open `/integrations/`.
2. Use **Test** or **Sync** beside the configured integration.

Testing requires `integrations.test_integration`; synchronization requires
`integrations.synchronize_integration`. File imports use the independent
`integrations.import_source_file` permission.

The current release does not provide a production-ready authentication method for unattended
REST API automation. Do not put account passwords in command lines; use the authenticated browser
session or the management commands below until a replacement API authentication method is
implemented.

For scheduled synchronization:

```bash
python manage.py sync_enabled_integrations
python manage.py sync_integration opencti-reports
```

## OpenCTI

```json
{
  "name": "OpenCTI reports",
  "slug": "opencti-reports",
  "kind": "threat_intelligence",
  "adapter_path": "integrations.adapters.opencti.OpenCtiReportsAdapter",
  "enabled": true,
  "configuration": {
    "base_url": "https://opencti.example.invalid",
    "page_size": 100,
    "timeout_seconds": 60,
    "max_batches_per_sync": 50,
    "project_records": true
  },
  "secret_reference": "env://OPENCTI"
}
```

Create a dedicated OpenCTI user for ThreatBridge and issue an API token for that user. The user must
not be an administrator or have bypass capabilities. Grant only the read permissions needed for
reports, markings, and the linked ATT&CK-pattern and vulnerability objects selected by the query.
The OpenCTI API grants the token the privileges of its associated user; administrator tokens are
outside the supported MVP boundary.

Have the deployment's secret provider inject `OPENCTI_TOKEN` and use
`secret_reference=env:OPENCTI_TOKEN` or `env://OPENCTI`. Alternatively, mount the token in a
non-symlink regular file readable only by the ThreatBridge account (mode `0600`) and use an absolute
reference such as `file:/run/secrets/opencti-token`. Secret files are limited to 64 KiB. Do not
place the token in source files, shell history, process arguments, integration configuration, the
base URL, logs, errors, database fields, synchronization cursors, or audit-event metadata.

ThreatBridge sends outbound requests to the explicitly configured OpenCTI base URL; it does not
require inbound OpenCTI callbacks. Production mode requires HTTPS and verifies the server TLS
certificate and hostname. The GraphQL endpoint defaults to `BASE_URL/graphql`; an override must
retain the same scheme, normalized hostname, and effective port. Proxies are disabled. Redirects
must remain same-origin and every redirect is revalidated against the outbound-host, DNS, and
private-CIDR policy.

The OpenCTI timeout is restricted to 1–120 seconds and page size to 1–500 records. Synchronization
also enforces `THREATBRIDGE_MAX_PAGES_PER_SYNC` and
`THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES`; keep these at bounded deployment-reviewed values. Invalid
JSON, malformed GraphQL connection shapes, and GraphQL error payloads fail with generic connector
errors rather than storing or returning vendor text.

The built-in GraphQL query imports reports, markings, linked ATT&CK patterns, and linked CVEs.
OpenCTI schemas can differ by release and extensions; set `configuration.query` to a
deployment-tested GraphQL query when an instance does not accept the default selection set.

All imported ATT&CK report mappings begin pending regardless of connector payload or configuration.
Approval and rejection require `catalog.review_attack_mapping` and create append-only review and
security events.

The built-in operation is read-only: it executes a GraphQL `query` and imports results. It does not
modify or delete OpenCTI objects, perform enrichment write-back, invoke export actions, or send
assessment results back to OpenCTI. Custom GraphQL text must remain a read query; operators must
review it before configuration.

For rotation, disable the integration, issue a replacement token for the same least-privileged
service account, update the environment or secret file, restart the ThreatBridge process so it
reloads the secret, test the integration, and then revoke the old token. Revoke a suspected exposed
token immediately in OpenCTI before investigating the ThreatBridge host.

## Microsoft Defender is deferred

Microsoft Defender is not an MVP integration and no Defender adapter is registered in this
release. Adding it would materially expand the trust boundary to production incidents, devices,
users, tenant telemetry, Entra application credentials, and potentially response actions. It
requires a separate design and security review; this release performs no Defender reads, writes,
remediation, or response actions.

## MITRE ATT&CK STIX

Download an official Enterprise ATT&CK STIX 2.1 bundle and place it below `THREATBRIDGE_DATA_DIR`, for example:

```text
data/incoming/enterprise-attack.json
```

Create the integration:

```json
{
  "name": "MITRE Enterprise ATT&CK",
  "slug": "mitre-enterprise-attack",
  "kind": "threat_intelligence",
  "adapter_path": "integrations.adapters.mitre_attack.MitreAttackStixAdapter",
  "enabled": true,
  "configuration": {
    "path": "incoming/enterprise-attack.json",
    "page_size": 500,
    "attack_version": "record-the-downloaded-release",
    "project_records": true
  }
}
```

The adapter only reads files inside `THREATBRIDGE_DATA_DIR`.

## Trivy

Generate a Trivy JSON result:

```bash
trivy image --format json --output data/incoming/trivy.json registry.example/app:1.2.3
```

Create the integration:

```json
{
  "name": "Trivy application image",
  "slug": "trivy-application-image",
  "kind": "vulnerability",
  "adapter_path": "integrations.adapters.trivy.TrivyJsonAdapter",
  "enabled": true,
  "configuration": {
    "path": "incoming/trivy.json",
    "project_records": true
  }
}
```

Use a separate profile per export or pipeline when independent evidence history is important.

## CSV and JSON sources

Use the browser at `/imports/new/`, the multipart API, or the command line.

```bash
python manage.py import_source_file examples/assets.csv \
  --name "Asset inventory CSV"

python manage.py import_source_file examples/assets.json \
  --name "Asset inventory JSON"

python manage.py import_source_file examples/assets.jsonl \
  --name "Asset inventory JSONL"
```

ThreatBridge automatically detects common collection wrappers such as `results`, `reports`, `assets`, `devices`, and `data.results`. It also recognizes common snake_case, camelCase, kebab-case, and dotted nested fields. When inference is not sufficient, specify the mapping explicitly:

```bash
python manage.py import_source_file vendor-export.json \
  --object-type vulnerability_finding \
  --records-key data.findings \
  --id-fields device.id,cve.id,package.version \
  --field-map '{
    "device.id": "asset_external_id",
    "device.name": "hostname",
    "cve.id": "cve_id",
    "package.name": "product",
    "package.version": "version"
  }'
```

A large mapping can be stored in a file:

```bash
python manage.py import_source_file vendor-export.json \
  --object-type asset \
  --field-map @config/vendor-asset-map.json
```

Refresh a reusable profile with a later export:

```bash
python manage.py import_source_file new-export.csv \
  --profile asset-inventory-csv
```

Add `--no-sync` to save the profile and source file without immediately importing it. Add `--strict-records` when one invalid record should fail the whole synchronization instead of being isolated as a record error.

Uploads and subsequent file reads enforce configured byte, record, nesting, object-field,
field-name, scalar, CSV-column/field, JSONL-line, preview, and retained-error limits. Archive or
compressed content, null bytes, traversal filenames, malformed encodings, and format/structure
conflicts are rejected. Malware scanning and quarantine are deployment requirements and are not
implemented here.

## Outbound network allow-list

Production deployments must set `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS` to the exact API hosts used by configured connectors:

```bash
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid
```

Plain HTTP connector URLs are rejected when `DJANGO_DEBUG=false`.

Privately hosted connectors require two independent approvals: the exact hostname or IP literal
must appear in `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS`, and every resolved address must fall within
`THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS`. For example, a synthetic on-premises OpenCTI
deployment would use:

```bash
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=opencti.example.invalid
THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS=10.20.0.0/16
```

CIDR permission never makes an unlisted hostname valid. Mixed public/private DNS answers are
rejected, as are loopback, link-local, multicast, unspecified, reserved, and cloud metadata
destinations even when a broad CIDR is configured. DNS is revalidated immediately before each
connection and on every same-origin redirect; redirects to another host, scheme, or port are
rejected.

Connector response bodies are limited by `THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES` before full
loading. Operator-facing errors retain bounded status/type information but omit response bodies,
request headers, query-string secrets, credentials, and resolved secret values.

## Secret references

Two environment-backed formats are supported:

```text
env:VARIABLE
```

The variable may contain a JSON object. For example, the secret provider can inject an object with
a `token` key. Its value must not be entered in a command line or committed configuration.

```text
env://PREFIX
```

All variables beginning with `PREFIX_` are returned to the adapter as lowercase keys. For example,
`OPENCTI_TOKEN` becomes `token` for `secret_reference=env://OPENCTI`.

An absolute `file:/path` reference reads a regular, non-symlink UTF-8 file that grants no group or
other permissions. The file may contain a plain value or a JSON object such as `{"token":"..."}`.

For production, replace the environment resolver with a managed secret provider while preserving the `secret_reference` contract.
