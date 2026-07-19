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
python manage.py sync_integration defender-vulnerabilities
```

## Microsoft Defender Vulnerability Management

ThreatBridge supports two independent Defender profiles because each profile maintains its own cursor and normalized object type.

### Vulnerability findings

`integration.json`:

```json
{
  "name": "Defender vulnerability findings",
  "slug": "defender-vulnerabilities",
  "kind": "vulnerability",
  "adapter_path": "integrations.adapters.defender_vm.DefenderVmAdapter",
  "enabled": true,
  "configuration": {
    "resource": "vulnerabilities",
    "base_url": "https://api.security.microsoft.com",
    "page_size": 50000,
    "project_records": true
  },
  "secret_reference": "env://DEFENDER"
}
```

### Software inventory

Use a second profile and change `resource` to `software_inventory`:

```json
{
  "name": "Defender software inventory",
  "slug": "defender-software",
  "kind": "asset",
  "adapter_path": "integrations.adapters.defender_vm.DefenderVmAdapter",
  "enabled": true,
  "configuration": {
    "resource": "software_inventory",
    "base_url": "https://api.security.microsoft.com",
    "page_size": 50000,
    "project_records": true
  },
  "secret_reference": "env://DEFENDER"
}
```

Have the deployment's secret provider inject `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, and
`DEFENDER_CLIENT_SECRET` into the ThreatBridge process. Do not type or store their values in shell
commands, checked-in files, or integration configuration.

The Entra application should receive only the read permissions required for the selected feeds. The current adapter uses the paged `SoftwareInventoryByMachine` and `SoftwareVulnerabilitiesByMachine` endpoints. For very large estates, add a bulk-export adapter before production rollout rather than raising page guardrails indefinitely.

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
    "project_records": true
  },
  "secret_reference": "env://OPENCTI"
}
```

Have the deployment's secret provider inject `OPENCTI_TOKEN` into the ThreatBridge process. Do not
place the token in source files, shell history, process arguments, or integration configuration.

The built-in GraphQL query imports reports, markings, linked ATT&CK patterns, and linked CVEs.
OpenCTI schemas can differ by release and extensions; set `configuration.query` to a
deployment-tested GraphQL query when an instance does not accept the default selection set.

All imported ATT&CK report mappings begin pending regardless of connector payload or configuration.
Approval and rejection require `catalog.review_attack_mapping` and create append-only review and
security events.

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
THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS=api.security.microsoft.com,login.microsoftonline.com,opencti.example.invalid
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

All variables beginning with `PREFIX_` are returned to the adapter as lowercase keys. For example, `DEFENDER_CLIENT_ID` becomes `client_id`.

For production, replace the environment resolver with a managed secret provider while preserving the `secret_reference` contract.
