# ThreatBridge integration contract

ThreatBridge separates source acquisition from canonical projection. Every live connector, file adapter, or manual ingestion path must produce the same stable source envelope.

## Adapter operations

Every integration adapter implements three operations:

1. `test_connection(context)` verifies credentials, reachability, scope, and source availability without changing source data.
2. `pull(context, cursor)` retrieves one complete page, export fragment, or bounded batch and returns the next durable cursor.
3. `normalize(context, raw_record)` converts one source record into a stable `SourceRecord`.

```python
from integrations.adapters.base import (
    IntegrationAdapter,
    PullBatch,
    SourceRecord,
    SyncContext,
)


class VendorAdapter(IntegrationAdapter):
    def test_connection(self, context: SyncContext) -> dict: ...

    def pull(self, context: SyncContext, cursor: dict) -> PullBatch: ...

    def normalize(
        self,
        context: SyncContext,
        raw_record: dict,
    ) -> SourceRecord: ...
```

## SourceRecord envelope

```python
SourceRecord(
    external_id="stable-vendor-identifier",
    object_type="vulnerability_finding",
    natural_key="CVE-2026-12345",
    source_updated_at=vendor_timestamp,
    raw=complete_vendor_record,
    normalized={
        "asset_external_id": "device-123",
        "cve_id": "CVE-2026-12345",
        "severity": "high",
    },
)
```

Required behavior:

- `external_id` must be stable across repeated imports.
- `object_type` must identify one supported canonical projector.
- `raw` must preserve the source evidence used for the normalized output.
- `normalized` must not contain credentials, access tokens, or private keys.
- `source_updated_at` should preserve the vendor timestamp when one exists.
- `natural_key` is optional and is intended for analyst search and correlation.

## Required connector guarantees

- Read-only by default.
- Cursors advance only after a source batch is completely processed.
- Vendor timestamps remain timezone-aware.
- Source records are idempotently upserted by integration, object type, and external ID.
- Connector-specific failures do not corrupt the previous successful cursor.
- Temporary network failures and throttling are handled inside the adapter or HTTP client.
- A connector never writes secret values to logs, sync metadata, source records, or exceptions.
- Response bodies are read with the centralized configured byte limit rather than unbounded
  `read()` calls.
- Deleted source keys remain deleted when they reappear during synchronization; only the explicit
  restoration service can reactivate them.
- Vendor write-back requires a separate, explicit design and permission boundary.

## PullBatch behavior

```python
PullBatch(
    records=[...],
    next_cursor={"after": "vendor-cursor"},
    complete=False,
    metadata={"vendor_page": 3},
)
```

An incomplete batch must advance its cursor. ThreatBridge rejects an adapter that returns `complete=False` without changing the cursor, preventing an infinite synchronization loop.

A file or completed export normally returns:

```python
PullBatch(
    records=[...],
    next_cursor={"file_sha256": "...", "complete": True},
    complete=True,
)
```

## Supported normalized object types

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

Observables are normally embedded in `threat_report` records to preserve source, confidence, and handling context.

## File adapters

The CSV and JSON adapters use the same synchronization contract as API connectors.

### CSV profile

```json
{
  "path": "incoming/uploads/2026/07/19/random.csv",
  "object_type": "software_installation",
  "id_fields": ["device_id", "software_name", "software_version"],
  "natural_key_field": "software_name",
  "updated_at_field": "updated_at",
  "delimiter": ",",
  "encoding": "utf-8-sig",
  "passthrough_unmapped": true,
  "field_map": {
    "device_id": "asset_external_id",
    "device_name": "hostname",
    "software_vendor": "vendor",
    "software_name": "product",
    "software_version": "version"
  }
}
```

### JSON profile

```json
{
  "path": "incoming/uploads/2026/07/19/random.json",
  "format": "json",
  "records_key": "data.results",
  "object_type": "asset",
  "id_fields": ["device.identity.id"],
  "passthrough_unmapped": true,
  "field_map": {
    "device.identity.id": "asset_external_id",
    "device.name": "hostname"
  }
}
```

JSON source paths can use dotted traversal. JSON Lines uses one object per non-empty line.

### Mixed-object envelope

```json
{
  "external_id": "finding-123",
  "object_type": "vulnerability_finding",
  "natural_key": "CVE-2026-12345",
  "source_updated_at": "2026-07-19T00:00:00Z",
  "normalized": {
    "asset_external_id": "device-123",
    "cve_id": "CVE-2026-12345",
    "severity": "high"
  }
}
```

Envelope mode supports multiple normalized object types in one JSON or JSON Lines file. The whole envelope is retained as the raw source record.

Imported threat-report ATT&CK mappings are always created pending. Adapters and payloads cannot set
approved, rejected, or uncertain review state. An authorized analyst must use the centralized
review transition service.

## Adding a connector

1. Add a class under `integrations/adapters/` or an approved installable package.
2. Extend `IntegrationAdapter`.
3. Add the dotted path to `BUILTIN_ADAPTERS` when it should appear in the adapter catalog.
4. Register an `Integration` row with the dotted class path and non-secret configuration.
5. Add contract tests for connection behavior, pagination/cursors, normalization, and idempotency.

No change to the core synchronization service is required.

## Secret references

`Integration.secret_reference` stores only a lookup reference. The built-in environment provider uses a reference such as:

```text
env://DEFENDER
```

and resolves variables such as:

```text
DEFENDER_TENANT_ID
DEFENDER_CLIENT_ID
DEFENDER_CLIENT_SECRET
```

Production deployments should replace or extend this resolver with an enterprise secret manager and short-lived credentials where supported.

## Current connector sequence

1. MITRE ATT&CK STIX import
2. Microsoft Defender Vulnerability Management inventory and vulnerability API
3. OpenCTI GraphQL reports and relationships
4. Trivy JSON imports
5. Generic CSV / JSON exports
6. Greenbone GMP reports
7. Securonix detections and alerts
8. CMDB or ServiceNow business-service mapping
9. ThreatWise or generic detection-validation results

The MVP includes working adapter entry points for items 1–5. Items 6–9 use the same contract and can be added without altering the source-evidence or assessment layers.
