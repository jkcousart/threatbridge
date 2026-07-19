# ThreatBridge

ThreatBridge is a vendor-neutral, threat-informed evidence and correlation application. It imports threat intelligence, asset inventory, software, vulnerability findings, detections, telemetry, and validation results; preserves the original source evidence; then produces explainable threat-to-control gap assessments.

This repository is a runnable MVP. It is intentionally read-only toward external security products.

## What is included

- Django web application and authenticated REST API
- Canonical catalog for assets, software, CVEs, ATT&CK techniques, telemetry, detections, validation evidence, threat reports, and observables
- Hashed source-record storage with provenance
- Idempotent synchronization, durable cursors, run history, and per-record error isolation
- Explainable assessment engine for exposure, telemetry, detection, and validation gaps
- Analyst review workflow for ATT&CK mappings in threat reports
- Bounded, format-validated CSV, JSON, JSONL, and NDJSON ingestion
- Schema preview, automatic object-type suggestions, field-map suggestions, and composite record IDs
- Reusable file-import profiles and a command-line import workflow
- Built-in adapters for:
  - MITRE ATT&CK STIX
  - Microsoft Defender Vulnerability Management
  - OpenCTI reports
  - Trivy JSON reports
  - Generic CSV
  - Generic JSON / JSON Lines
  - Credential-free demonstration data
- SQLite development mode and PostgreSQL Docker Compose deployment

## Quick start

Requires Python 3.12 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
python manage.py migrate
python manage.py seed_demo
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`, sign in, and inspect the seeded report and assessment.

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

Staff users can open `/imports/new/` and:

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

Use `python manage.py import_source_file --help` for records-key, delimiter, review-state,
strict-record, and no-sync options.

## Authenticated file upload

Only staff users can preview or import files.

Sign in through `/accounts/login/`, then open `/imports/new/` to preview, import, and
synchronize a file with the authenticated browser session. This keeps the password out of
source files, shell history, and process arguments.

The current release does not provide a production-ready authentication method for unattended
REST API automation. Do not automate the file-upload API with command-line passwords; use the
browser workflow or the management command below until a replacement API authentication method
is implemented.

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

See [`docs/integration-contract.md`](docs/integration-contract.md) for the adapter contract and [`docs/integration-setup.md`](docs/integration-setup.md) for Defender, OpenCTI, MITRE ATT&CK, Trivy, and scheduled file-import examples.

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `DJANGO_DEBUG` | Development mode | `true` |
| `DJANGO_SECRET_KEY` | Django signing key; required outside development | Generated in `.secrets/` during development |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated hosts | `localhost,127.0.0.1` |
| `DJANGO_CSRF_TRUSTED_ORIGINS` | Comma-separated origins | Empty |
| `DJANGO_TIME_ZONE` | Display/default timezone | `UTC` |
| `DATABASE_URL` | SQLite or PostgreSQL connection | Local SQLite |
| `THREATBRIDGE_DATA_DIR` | Connector and upload data directory | `./data` |
| `THREATBRIDGE_MAX_UPLOAD_BYTES` | Multipart file-size limit | `52428800` |
| `THREATBRIDGE_MAX_IMPORT_RECORDS` | Records allowed in one file import | `100000` |
| `THREATBRIDGE_MAX_PAGES_PER_SYNC` | Connector page guardrail | `50` |
| `THREATBRIDGE_ALLOWED_ADAPTER_PREFIXES` | Allowed Python adapter namespaces | `integrations.adapters.` |
| `THREATBRIDGE_ALLOWED_OUTBOUND_HOSTS` | Exact connector destination hostnames or IP literals | Empty |
| `THREATBRIDGE_ALLOWED_PRIVATE_OUTBOUND_CIDRS` | Private CIDRs permitted for exact allowlisted hosts | Empty |

## Security boundaries

- External integrations are read-only by design.
- File uploads are restricted to staff users, accepted extensions, configured size/record limits, and a server-controlled path under `THREATBRIDGE_DATA_DIR`.
- Uploaded filenames are not used as storage paths; ThreatBridge generates random names and stores the original name as metadata.
- Credentials are not stored in integration configuration. `secret_reference` resolves credentials from an external source such as environment variables.
- Every connector destination requires an exact outbound-host allowlist entry. Private destinations additionally require every DNS answer to fall within an explicitly allowed private CIDR.
- Each `ExternalObject` row retains the latest raw and normalized version for its integration/type/external-ID key, with a content hash and provenance timestamps; it is not an append-only version history.
- Write-back, automatic blocking, rule deployment, scan execution, and remediation are outside the MVP.
- Do not ingest PHI, patient records, secrets, access tokens, or private keys.
- Malware scanning and quarantine are not implemented. Production deployments must add both before accepting untrusted uploads.

For production, add enterprise SSO, a managed secret provider, centralized logging, backup/restore, asynchronous workers for large imports, retention controls, and organization-specific authorization scopes.

## Tests and checks

```bash
ruff check threatbridge integrations catalog
python manage.py check
python manage.py makemigrations --check --dry-run
pytest -q
```

A clean smoke test can also be run with:

```bash
python manage.py migrate
python manage.py seed_demo
```
