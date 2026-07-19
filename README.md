# ThreatBridge

ThreatBridge is a vendor-neutral, threat-informed evidence and correlation application. It imports threat intelligence, asset inventory, software, vulnerability findings, detections, telemetry, and validation results; stores the latest hashed source record with provenance; then produces explainable threat-to-control gap assessments.

ThreatBridge is not a control-plane or response-automation system. It is
intentionally read-only toward external security products. ThreatBridge is
licensed under Apache-2.0, as approved by the project owner for public source
distribution.

## What is included

- Django web application and authenticated REST API
- Canonical catalog for assets, software, CVEs, ATT&CK techniques, telemetry, detections, validation evidence, threat reports, and observables
- Hashed source-record storage with provenance
- Idempotent synchronization, durable cursors, run history, and per-record error isolation
- Explainable assessment engine for exposure, telemetry, detection, and validation gaps
- Analyst review workflow for ATT&CK mappings in threat reports
- Central named-permission policy and structured, redacted security audit events
- Recoverable source-evidence deletion with independently permissioned restoration
- Bounded, format-validated CSV, JSON, JSONL, and NDJSON ingestion
- Schema preview, automatic object-type suggestions, field-map suggestions, and composite record IDs
- Reusable file-import profiles and a command-line import workflow
- Built-in adapters for:
  - MITRE ATT&CK STIX
  - OpenCTI reports
  - Trivy JSON reports
  - Generic CSV
  - Generic JSON / JSON Lines
  - Credential-free demonstration data
- SQLite development mode and PostgreSQL Docker Compose deployment

## Quick start

Requires CPython 3.12, 3.13, or 3.14.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/build.txt
python -m pip install --require-hashes -r requirements/development.txt
python -m pip install --no-deps --no-build-isolation -e .
cp .env.example .env
python manage.py migrate
python manage.py seed_demo
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`, sign in, and inspect the seeded report and assessment.

The lock files are generated from `pyproject.toml`; do not edit them by hand. See
[`docs/dependency-locking.md`](docs/dependency-locking.md) for installation, consistency checks,
and the controlled update procedure.

Useful routes:

- Dashboard: `/`
- Threat reports: `/reports/`
- Integrations: `/integrations/`
- CSV / JSON import: `/imports/new/`
- Source evidence: `/evidence/`
- Django administration: `/admin/`
- REST API root: `/api/`
- Health: `/healthz`
- Readiness: `/readyz`

## Docker Compose

```bash
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
docker compose exec web python manage.py seed_demo
```

Then open `http://127.0.0.1:8000/`.

The Compose values are for local evaluation only. Development mode generates a persistent local
Django secret inside the container. Before using a shared environment, replace the database
password, set `DJANGO_DEBUG=false`, and provide `DJANGO_SECRET_KEY` explicitly.

## Importing CSV and JSON

Users granted `integrations.import_source_file` can open `/imports/new/` and:

1. Select a CSV, JSON, JSONL, or NDJSON file.
2. Preview the record count, fields, and sample objects.
3. Accept or adjust the suggested object type and stable ID fields.
4. Review the suggested source-to-canonical field map.
5. Upload and immediately project the records.

The resulting `Integration` is retained as a reusable profile. Use **Upload file** on the Integrations page to refresh that profile with a later export.

### CSV example

```csv
device_id,device_name,operating_system,criticality,last_seen
asset-001,server-01.example,Windows Server 2022,critical,2026-07-18T12:00:00Z
asset-002,server-02.example,Linux,high,2026-07-18T12:05:00Z
```

For a vulnerability export, use a composite identifier such as:

```text
device_id,cve_id,software_name,software_version
```

### Ordinary JSON example

```json
{
  "results": [
    {
      "deviceId": "asset-001",
      "deviceName": "server-01.example",
      "platform": "Windows Server 2022",
      "criticality": "critical"
    }
  ]
}
```

Set the JSON records key to `results`, use `deviceId` as the stable ID, and map:

```json
{
  "deviceId": "asset_external_id",
  "deviceName": "hostname",
  "platform": "os_platform"
}
```

Dotted source paths are supported for JSON, for example `device.identity.id`.
ThreatBridge automatically recognizes common collection wrappers including `records`,
`results`, `reports`, `assets`, `devices`, `findings`, and one-level nested wrappers such
as `data.results`. You can always override detection with the **JSON records key** field.

JSON Lines and NDJSON are also supported. Each non-empty line must contain one JSON object.
See [`examples/assets.json`](examples/assets.json) and
[`examples/assets.jsonl`](examples/assets.jsonl).

### Mixed ThreatBridge envelope

One JSON or JSON Lines file can contain multiple object types:

```json
[
  {
    "external_id": "asset-001",
    "object_type": "asset",
    "natural_key": "server-01",
    "source_updated_at": "2026-07-18T12:00:00Z",
    "normalized": {
      "asset_external_id": "asset-001",
      "hostname": "server-01.example",
      "criticality": "critical"
    }
  },
  {
    "external_id": "vulnerability-cve-2026-9999",
    "object_type": "vulnerability",
    "natural_key": "CVE-2026-9999",
    "normalized": {
      "cve_id": "CVE-2026-9999",
      "title": "Example vulnerability",
      "severity": "high"
    }
  }
]
```

Choose **ThreatBridge JSON envelope (mixed object types)**. Every envelope keeps its original source object and projects its `normalized` payload through the same canonical model used by live integrations.

Sample files are in [`examples/`](examples/).

## Command-line file import

Files can also be imported without the browser. The command uses the same preview,
normalization, evidence, synchronization, and projection pipeline as the web and REST APIs.

```bash
python manage.py import_source_file examples/assets.csv \
  --name "Asset inventory export"

python manage.py import_source_file examples/assets.json \
  --name "JSON asset inventory"

python manage.py import_source_file examples/assets.jsonl \
  --name "Nested JSONL inventory" \
  --object-type asset \
  --id-fields device.identity.id \
  --field-map '{"device.identity.id":"asset_external_id","device.name":"hostname","device.platform":"os_platform"}'
```

Refresh an existing reusable profile with a new export by supplying its slug:

```bash
python manage.py import_source_file ./new-export.csv --profile asset-inventory-export
```

Use `python manage.py import_source_file --help` for records-key, delimiter, strict-record, and
no-sync options. ATT&CK mappings embedded in any imported threat report always begin pending.

## Authenticated file upload

Only users with `integrations.import_source_file` can preview or import files. Django staff status
alone does not grant this or any other application workflow.

Sign in through `/accounts/login/`, then open `/imports/new/` to preview, import, and
synchronize a file with the authenticated browser session. This keeps the password out of
source files, shell history, and process arguments.

The REST API accepts authenticated Django browser sessions only. HTTP Basic Authentication is
disabled, and unsafe session-authenticated API requests require CSRF protection. The current
release does not provide production-ready unattended API authentication. Do not automate the API
with command-line passwords; use the browser workflow or an appropriately controlled management
command until a replacement authentication method is designed.

### Command-line file import

Scheduled jobs and pipelines can use the same validated import path as the browser:

```bash
python manage.py import_source_file examples/assets.csv --name "Asset inventory CSV"
python manage.py import_source_file examples/assets.json --name "Asset inventory JSON"
python manage.py import_source_file examples/assets.jsonl --name "Asset inventory JSONL"
```

Use `--records-key data.results`, `--id-fields device.id,cve.id`, or
`--field-map @mapping.json` when a vendor export needs an explicit profile. Refresh a
reusable profile with `--profile PROFILE_SLUG`.

Other authenticated API operations:

- `GET /api/integrations/`
- `POST /api/integrations/{id}/test/`
- `POST /api/integrations/{id}/sync/`
- `GET /api/sync-runs/`
- `GET /api/external-objects/`
- `GET /api/catalog/`

Integration viewing, configuration, testing, synchronization, imports, assessments, ATT&CK review,
restricted/deleted evidence, restoration, and audit-event access each have separate named
permissions. See [`docs/authorization-model.md`](docs/authorization-model.md).

## Normalized object types

The generic file adapters can project:

- `asset`
- `software_installation`
- `vulnerability`
- `vulnerability_finding`
- `attack_technique`
- `telemetry_source`
- `detection_rule`
- `validation_test`
- `validation_result`
- `threat_report`

Observables are embedded in threat reports so their source, confidence, and handling marking remain attached to the report.

## Integration architecture

```text
Vendor API / export / uploaded file
                |
                v
        Integration adapter
                |
                v
  ExternalObject source evidence
  - raw record
  - normalized record
  - source timestamp
  - content hash
  - projection status
                |
                v
        Canonical catalog
  Assets / CVEs / ATT&CK / rules /
  telemetry / tests / reports
                |
                v
      Explainable assessment
  exposure + visibility + detection
          + validation gaps
```

Each adapter implements:

```python
class IntegrationAdapter:
    def test_connection(self, context): ...
    def pull(self, context, cursor): ...
    def normalize(self, context, raw_record): ...
```

See [`docs/integration-contract.md`](docs/integration-contract.md) for the adapter contract and
[`docs/integration-setup.md`](docs/integration-setup.md) for the supported OpenCTI MVP boundary,
MITRE ATT&CK, Trivy, and scheduled file-import examples. Microsoft Defender is explicitly deferred
from this release.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DJANGO_DEBUG` | Development mode | `true` |
| `DJANGO_SECRET_KEY` | Django signing key; required outside development | Generated in `.secrets/` during development |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hosts | `localhost,127.0.0.1` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Comma-separated origins | Empty |
| `DJANGO_SECURE_HSTS_SECONDS` | Explicit production HSTS duration | Required in production |
| `DJANGO_TRUST_X_FORWARDED_PROTO` | Trust a stripping proxy's forwarded HTTPS header | `false` |
| `DJANGO_TIME_ZONE` | Display/default timezone | `UTC` |
| `DATABASE_URL` | SQLite or PostgreSQL connection | Local SQLite |
| `THREATBRIDGE_DATA_DIR` | Connector and upload data directory | `./data` |
| `THREATBRIDGE_MAX_UPLOAD_BYTES` | Multipart file-size limit | `52428800` |
| `THREATBRIDGE_MAX_IMPORT_RECORDS` | Records allowed in one file import | `100000` |
| `THREATBRIDGE_MAX_HTTP_RESPONSE_BYTES` | Maximum connector response body | `10485760` |
| `THREATBRIDGE_MAX_JSON_DEPTH` | Maximum imported JSON nesting | `20` |
| `THREATBRIDGE_MAX_OBJECT_FIELDS` | Maximum fields in one JSON object | `500` |
| `THREATBRIDGE_MAX_FIELD_NAME_LENGTH` | Maximum imported field-name length | `200` |
| `THREATBRIDGE_MAX_SCALAR_LENGTH` | Maximum imported JSON string length | `100000` |
| `THREATBRIDGE_MAX_CSV_COLUMNS` | Maximum CSV columns | `500` |
| `THREATBRIDGE_MAX_CSV_FIELD_LENGTH` | Maximum CSV field length | `100000` |
| `THREATBRIDGE_MAX_JSONL_LINE_BYTES` | Maximum JSONL/NDJSON line bytes | `1048576` |
| `THREATBRIDGE_MAX_PREVIEW_SAMPLES` | Maximum preview records returned | `5` |
| `THREATBRIDGE_MAX_IMPORT_ERRORS` | Maximum per-record errors retained per run | `100` |
| `THREATBRIDGE_MAX_PAGES_PER_SYNC` | Connector page guardrail | `50` |
| `THREATBRIDGE_ALLOWED_ADAPTER_PREFIXES` | Allowed Python adapter namespaces | `integrations.adapters.` |
| `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS` | Exact connector destination hostnames or IP literals | Empty |
| `THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS` | Private CIDRs permitted for exact allowlisted hosts | Empty |

## Security boundaries

- External integrations are read-only by design.
- File uploads require a named permission and enforce byte, record, structure, nesting, field,
  line, preview, and retained-error limits under a server-controlled path.
- Uploaded filenames are not used as storage paths; ThreatBridge generates random names and stores the original name as metadata.
- Credentials are not stored in integration configuration. `secret_reference` resolves credentials from an external source such as environment variables.
- Every connector destination requires an exact outbound-host allowlist entry. Private destinations additionally require every DNS answer to fall within an explicitly allowed private CIDR.
- Connector response bodies are bounded before complete in-memory loading, and stored/displayed
  connector failures omit bodies, query strings, headers, and resolved secrets.
- Each `ExternalObject` row retains the latest raw and normalized version for its integration/type/external-ID key, with a content hash and provenance timestamps; it is not an append-only version history.
- Imported, synchronized, manually entered, API-created, and reprojected ATT&CK mappings always
  begin pending; only the review service can approve or reject them.
- Deleted evidence is hidden from ordinary views, APIs, projections, reprojection, and assessment;
  restoration requires a separate permission and both lifecycle actions are audited.
- Assessments record complete active-evidence provenance; legacy assessments without that manifest
  remain hidden until explicitly recalculated.
- Security audit events and ATT&CK review events are append-only through application and admin
  paths, with bounded redacted metadata.
- Write-back, automatic blocking, rule deployment, scan execution, and remediation are outside the MVP.
- Do not ingest PHI, patient records, secrets, access tokens, or private keys.
- Malware scanning and quarantine are not implemented. Production deployments must add both before accepting untrusted uploads.

Production requirements and fail-closed settings are documented in
[`docs/deployment-hardening.md`](docs/deployment-hardening.md). Tenant isolation, organization
scoping, Entra ID/enterprise SSO, full TLP enforcement, automatic policy decisions, connector
write-back, and automatic remediation are not implemented.

## Tests and checks

```bash
bash scripts/security_check.sh
```

A clean smoke test can also be run with:

```bash
python manage.py migrate
python manage.py seed_demo
```

## Licence

ThreatBridge is prepared for distribution under the
[Apache License, Version 2.0](LICENSE). Copyright 2026 ThreatBridge contributors. See
[`NOTICE`](NOTICE) for the project notice.

The project owner approved the license selection, copyright attribution,
project name, notices, contribution terms, and public source distribution.
Prebuilt container publication remains subject to the image vulnerability
policy documented in `docs/container-image-security.md`.

Container artifact provenance, image SBOM generation, and vulnerability-disposition policy are
documented in [`docs/container-image-security.md`](docs/container-image-security.md).
