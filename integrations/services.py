from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from catalog.services.materialize import materialize_external_object

from .adapters.base import SourceRecord, SyncContext
from .models import ExternalObject, Integration, SyncRecordError, SyncRun
from .registry import load_adapter
from .secrets import redacted_result, resolve_secret_reference

logger = logging.getLogger(__name__)


def _json_default(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _content_hash(record: SourceRecord) -> str:
    payload = {
        "object_type": record.object_type,
        "external_id": record.external_id,
        "natural_key": record.natural_key,
        "source_updated_at": record.source_updated_at,
        "raw": record.raw,
        "normalized": record.normalized,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=_json_default)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _context(integration: Integration) -> SyncContext:
    return SyncContext(
        integration_slug=integration.slug,
        configuration=integration.configuration,
        secret_reference=integration.secret_reference,
        secrets=resolve_secret_reference(integration.secret_reference),
    )


def _raw_summary(raw_record: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"keys": sorted(str(key) for key in raw_record.keys())[:100]}
    for key in ("id", "external_id", "deviceId", "cveId", "name", "title"):
        if raw_record.get(key) not in (None, ""):
            result[key] = str(raw_record[key])[:500]
    return result


def test_integration(integration: Integration) -> Mapping[str, Any]:
    adapter = load_adapter(integration.adapter_path)
    try:
        result = redacted_result(dict(adapter.test_connection(_context(integration))))
        ok = bool(result.get("ok", True))
        integration.health = (
            Integration.Health.HEALTHY if ok else Integration.Health.DEGRADED
        )
        integration.last_error = (
            ""
            if ok
            else str(result.get("error", "Connection test reported a problem"))[:4000]
        )
    except Exception as exc:
        integration.health = Integration.Health.ERROR
        integration.last_error = str(exc)[:4000]
        integration.last_tested_at = timezone.now()
        integration.last_test_result = {"ok": False, "error": str(exc)[:1000]}
        integration.save(
            update_fields=[
                "health",
                "last_error",
                "last_tested_at",
                "last_test_result",
                "updated_at",
            ]
        )
        raise

    integration.last_tested_at = timezone.now()
    integration.last_test_result = result
    integration.save(
        update_fields=[
            "health",
            "last_error",
            "last_tested_at",
            "last_test_result",
            "updated_at",
        ]
    )
    return result


def _store_record(integration: Integration, record: SourceRecord) -> tuple[ExternalObject, str]:
    external_id = str(record.external_id).strip()
    object_type = str(record.object_type).strip()
    if not external_id or not object_type:
        raise ValueError("Normalized record requires external_id and object_type")

    digest = _content_hash(record)
    lookup = {
        "integration": integration,
        "object_type": object_type,
        "external_id": external_id,
    }
    source_object = ExternalObject.objects.filter(**lookup).first()
    defaults = {
        "natural_key": str(record.natural_key or ""),
        "source_updated_at": record.source_updated_at,
        "raw": dict(record.raw),
        "normalized": dict(record.normalized),
        "content_hash": digest,
        "is_deleted": False,
    }

    if source_object is None:
        source_object = ExternalObject.objects.create(
            **lookup,
            **defaults,
            projection_status=ExternalObject.ProjectionStatus.PENDING,
        )
        return source_object, "created"

    if source_object.content_hash == digest and not source_object.is_deleted:
        source_object.last_seen_at = timezone.now()
        source_object.save(update_fields=["last_seen_at"])
        return source_object, "unchanged"

    for field_name, value in defaults.items():
        setattr(source_object, field_name, value)
    source_object.projection_status = ExternalObject.ProjectionStatus.PENDING
    source_object.projection_error = ""
    source_object.projected_at = None
    source_object.save()
    return source_object, "updated"


def project_external_object(source_object: ExternalObject) -> tuple[str, Any | None]:
    """Materialize one source object and persist its projection state."""

    try:
        projected = materialize_external_object(source_object)
    except Exception as exc:
        source_object.projection_status = ExternalObject.ProjectionStatus.FAILED
        source_object.projection_error = str(exc)[:4000]
        source_object.projected_at = timezone.now()
        source_object.save(
            update_fields=["projection_status", "projection_error", "projected_at"]
        )
        raise

    source_object.projection_status = (
        ExternalObject.ProjectionStatus.SKIPPED
        if projected is None
        else ExternalObject.ProjectionStatus.PROJECTED
    )
    source_object.projection_error = ""
    source_object.projected_at = timezone.now()
    source_object.save(
        update_fields=["projection_status", "projection_error", "projected_at"]
    )
    return source_object.projection_status, projected


def _record_error(
    run: SyncRun,
    *,
    stage: str,
    exc: Exception,
    raw_record: Mapping[str, Any],
    record: SourceRecord | None = None,
) -> None:
    SyncRecordError.objects.create(
        sync_run=run,
        stage=stage,
        object_type=record.object_type if record else "",
        external_id=record.external_id if record else "",
        error_type=type(exc).__name__,
        error_message=str(exc)[:4000],
        raw_summary=_raw_summary(raw_record),
    )


def run_integration_sync(integration: Integration) -> SyncRun:
    if not integration.enabled:
        raise ValueError(f"Integration {integration.slug} is disabled")
    if SyncRun.objects.filter(
        integration=integration,
        status=SyncRun.Status.RUNNING,
    ).exists():
        raise ValueError(f"Integration {integration.slug} already has a running synchronization")

    run = SyncRun.objects.create(
        integration=integration,
        cursor_before=dict(integration.cursor),
    )
    integration.last_attempt_at = timezone.now()
    integration.save(update_fields=["last_attempt_at", "updated_at"])

    adapter = load_adapter(integration.adapter_path)
    context = _context(integration)
    current_cursor: Mapping[str, Any] = dict(integration.cursor)
    strict_records = bool(integration.configuration.get("strict_records", False))
    strict_projection = bool(integration.configuration.get("strict_projection", False))
    project_records = bool(integration.configuration.get("project_records", True))
    configured_limit = int(
        integration.configuration.get(
            "max_batches_per_sync",
            getattr(settings, "THREATBRIDGE_MAX_PAGES_PER_SYNC", 50),
        )
    )
    max_batches = max(1, min(configured_limit, 1000))
    batch_metadata: list[Mapping[str, Any]] = []
    bounded = False

    counters = {
        "received": 0,
        "accepted": 0,
        "rejected": 0,
        "created": 0,
        "updated": 0,
        "unchanged": 0,
        "projected": 0,
        "projection_failures": 0,
    }

    try:
        for batch_number in range(1, max_batches + 1):
            batch = adapter.pull(context, current_cursor)
            raw_records = list(batch.records)
            counters["received"] += len(raw_records)
            batch_metadata.append(
                {
                    **batch.combined_metadata,
                    "batch": batch_number,
                    "record_count": len(raw_records),
                    "complete": batch.is_complete,
                }
            )

            for raw_record in raw_records:
                if not isinstance(raw_record, Mapping):
                    exc = TypeError("Adapter pull records must be mappings")
                    _record_error(
                        run,
                        stage=SyncRecordError.Stage.NORMALIZE,
                        exc=exc,
                        raw_record={"value": str(raw_record)[:500]},
                    )
                    counters["rejected"] += 1
                    if strict_records:
                        raise exc
                    continue

                record: SourceRecord | None = None
                try:
                    record = adapter.normalize(context, raw_record)
                except Exception as exc:
                    _record_error(
                        run,
                        stage=SyncRecordError.Stage.NORMALIZE,
                        exc=exc,
                        raw_record=raw_record,
                    )
                    counters["rejected"] += 1
                    logger.warning(
                        "Integration record normalization failed",
                        extra={
                            "integration": integration.slug,
                            "error_type": type(exc).__name__,
                        },
                    )
                    if strict_records:
                        raise
                    continue

                try:
                    with transaction.atomic():
                        source_object, disposition = _store_record(integration, record)
                    counters[disposition] += 1
                    counters["accepted"] += 1
                except Exception as exc:
                    _record_error(
                        run,
                        stage=SyncRecordError.Stage.STORE,
                        exc=exc,
                        raw_record=raw_record,
                        record=record,
                    )
                    counters["rejected"] += 1
                    if strict_records:
                        raise
                    continue

                should_project = project_records and (
                    disposition != "unchanged"
                    or source_object.projection_status
                    in {
                        ExternalObject.ProjectionStatus.PENDING,
                        ExternalObject.ProjectionStatus.FAILED,
                    }
                )
                if should_project:
                    try:
                        projection_status, _projected = project_external_object(source_object)
                        if projection_status == ExternalObject.ProjectionStatus.PROJECTED:
                            counters["projected"] += 1
                    except Exception as exc:
                        _record_error(
                            run,
                            stage=SyncRecordError.Stage.PROJECT,
                            exc=exc,
                            raw_record=raw_record,
                            record=record,
                        )
                        counters["projection_failures"] += 1
                        logger.warning(
                            "Integration record projection failed",
                            extra={
                                "integration": integration.slug,
                                "object_type": record.object_type,
                                "external_id": record.external_id,
                            },
                        )
                        if strict_projection:
                            raise

            next_cursor = dict(batch.next_cursor)
            if not batch.is_complete and next_cursor == dict(current_cursor):
                raise RuntimeError(
                    "Adapter returned an incomplete batch without advancing its cursor"
                )
            current_cursor = next_cursor
            run.batches_processed = batch_number
            if batch.is_complete:
                break
        else:
            bounded = True
            batch_metadata.append(
                {
                    "bounded": True,
                    "reason": "max_batches_per_sync reached",
                    "max_batches": max_batches,
                }
            )

        integration.cursor = dict(current_cursor)
        integration.last_success_at = timezone.now()
        has_quality_issues = bool(
            counters["rejected"] or counters["projection_failures"] or bounded
        )
        integration.health = (
            Integration.Health.DEGRADED
            if has_quality_issues
            else Integration.Health.HEALTHY
        )
        integration.last_error = ""
        integration.save(
            update_fields=[
                "cursor",
                "last_success_at",
                "health",
                "last_error",
                "updated_at",
            ]
        )

        run.status = SyncRun.Status.PARTIAL if has_quality_issues else SyncRun.Status.SUCCEEDED
        run.finished_at = timezone.now()
        run.cursor_after = dict(current_cursor)
        run.records_received = counters["received"]
        run.records_accepted = counters["accepted"]
        run.records_rejected = counters["rejected"]
        run.records_created = counters["created"]
        run.records_updated = counters["updated"]
        run.records_unchanged = counters["unchanged"]
        run.records_projected = counters["projected"]
        run.projection_failures = counters["projection_failures"]
        run.metadata = {"batches": batch_metadata, "bounded": bounded}
        run.save()
        return run
    except Exception as exc:
        run.status = SyncRun.Status.FAILED
        run.finished_at = timezone.now()
        run.cursor_after = dict(integration.cursor)
        run.records_received = counters["received"]
        run.records_accepted = counters["accepted"]
        run.records_rejected = counters["rejected"]
        run.records_created = counters["created"]
        run.records_updated = counters["updated"]
        run.records_unchanged = counters["unchanged"]
        run.records_projected = counters["projected"]
        run.projection_failures = counters["projection_failures"]
        run.error_summary = str(exc)[:4000]
        run.metadata = {"batches": batch_metadata, "bounded": bounded}
        run.save()
        integration.health = Integration.Health.ERROR
        integration.last_error = str(exc)[:4000]
        integration.save(update_fields=["health", "last_error", "updated_at"])
        raise


def ingest_source_record(
    integration: Integration,
    record: SourceRecord,
    *,
    project: bool = True,
) -> tuple[ExternalObject, str, str | None, Any | None]:
    """Store one already-normalized record, primarily for manual/API ingestion."""

    with transaction.atomic():
        source_object, disposition = _store_record(integration, record)
    projection_status: str | None = None
    projected: Any | None = None
    if project:
        projection_status, projected = project_external_object(source_object)
    return source_object, disposition, projection_status, projected
