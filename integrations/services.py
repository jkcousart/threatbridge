from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from catalog.services.audit import record_security_event
from catalog.services.materialize import materialize_external_object
from threatbridge.authorization import (
    Permissions,
    require_operation_permission,
)

from .adapters.base import SourceRecord, SyncContext
from .models import ExternalObject, Integration, SyncRecordError, SyncRun
from .registry import load_adapter
from .secrets import (
    redacted_result,
    resolve_secret_reference,
    sanitized_connector_error,
    validate_safe_cursor,
)

logger = logging.getLogger(__name__)


class DeletedSourceEvidenceError(ValueError):
    pass


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
    return {"keys": sorted(str(key) for key in raw_record.keys())[:100]}


def test_integration(
    integration: Integration,
    *,
    actor=None,
    origin: str,
    system: bool = False,
) -> Mapping[str, Any]:
    require_operation_permission(
        actor,
        Permissions.TEST_INTEGRATIONS,
        origin=origin,
        system=system,
    )
    record_security_event(
        event_type="integration.test_started",
        origin=origin,
        outcome="started",
        actor=actor,
        target_type="integration",
        target_identifier=integration.pk,
    )
    try:
        adapter = load_adapter(integration.adapter_path)
        context = _context(integration)
        result = redacted_result(
            dict(adapter.test_connection(context)),
            resolved_secrets=context.secrets,
        )
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
        safe_error = sanitized_connector_error(exc)
        integration.health = Integration.Health.ERROR
        integration.last_error = safe_error
        integration.last_tested_at = timezone.now()
        integration.last_test_result = {"ok": False, "error": safe_error}
        integration.save(
            update_fields=[
                "health",
                "last_error",
                "last_tested_at",
                "last_test_result",
                "updated_at",
            ]
        )
        record_security_event(
            event_type="integration.test_completed",
            origin=origin,
            outcome="failed",
            actor=actor,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"error_type": type(exc).__name__},
        )
        raise RuntimeError(safe_error) from None

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
    record_security_event(
        event_type="integration.test_completed",
        origin=origin,
        outcome="succeeded" if result.get("ok", True) else "degraded",
        actor=actor,
        target_type="integration",
        target_identifier=integration.pk,
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
    source_object = ExternalObject.all_objects.filter(**lookup).first()
    defaults = {
        "natural_key": str(record.natural_key or ""),
        "source_updated_at": record.source_updated_at,
        "raw": dict(record.raw),
        "normalized": dict(record.normalized),
        "content_hash": digest,
    }

    if source_object is None:
        source_object = ExternalObject.objects.create(
            **lookup,
            **defaults,
            projection_status=ExternalObject.ProjectionStatus.PENDING,
        )
        return source_object, "created"

    if source_object.is_deleted:
        source_object.last_seen_at = timezone.now()
        source_object.save(update_fields=["last_seen_at"])
        return source_object, "unchanged"

    if source_object.content_hash == digest:
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


def project_external_object(
    source_object: ExternalObject,
    *,
    actor=None,
    origin: str,
    system: bool = False,
    operation_permission: str = Permissions.SYNCHRONIZE_INTEGRATIONS,
) -> tuple[str, Any | None]:
    """Materialize one source object and persist its projection state."""

    require_operation_permission(
        actor,
        operation_permission,
        origin=origin,
        system=system,
    )
    try:
        with transaction.atomic():
            refreshed = (
                ExternalObject.all_objects.select_for_update()
                .select_related("integration")
                .get(pk=source_object.pk)
            )
            if refreshed.is_deleted:
                raise DeletedSourceEvidenceError(
                    "Deleted source evidence cannot be projected."
                )
            projected = materialize_external_object(refreshed)
            refreshed.projection_status = (
                ExternalObject.ProjectionStatus.SKIPPED
                if projected is None
                else ExternalObject.ProjectionStatus.PROJECTED
            )
            refreshed.projection_error = ""
            refreshed.projected_at = timezone.now()
            refreshed.save(
                update_fields=[
                    "projection_status",
                    "projection_error",
                    "projected_at",
                ]
            )
    except DeletedSourceEvidenceError:
        raise
    except Exception as exc:
        safe_error = sanitized_connector_error(exc)
        with transaction.atomic():
            refreshed = ExternalObject.all_objects.select_for_update().get(
                pk=source_object.pk
            )
            if refreshed.is_deleted:
                raise DeletedSourceEvidenceError(
                    "Deleted source evidence cannot be projected."
                ) from None
            refreshed.projection_status = ExternalObject.ProjectionStatus.FAILED
            refreshed.projection_error = safe_error
            refreshed.projected_at = timezone.now()
            refreshed.save(
                update_fields=[
                    "projection_status",
                    "projection_error",
                    "projected_at",
                ]
            )
        raise RuntimeError(safe_error) from None

    return refreshed.projection_status, projected


def _record_error(
    run: SyncRun,
    *,
    stage: str,
    exc: Exception,
    raw_record: Mapping[str, Any],
    record: SourceRecord | None = None,
) -> None:
    maximum = int(getattr(settings, "THREATBRIDGE_MAX_IMPORT_ERRORS", 100))
    if run.record_errors.count() >= maximum:
        return
    SyncRecordError.objects.create(
        sync_run=run,
        stage=stage,
        object_type=record.object_type if record else "",
        external_id=record.external_id if record else "",
        error_type=type(exc).__name__,
        error_message=sanitized_connector_error(exc),
        raw_summary=_raw_summary(raw_record),
    )


def run_integration_sync(
    integration: Integration,
    *,
    actor=None,
    origin: str,
    system: bool = False,
    operation_permission: str = Permissions.SYNCHRONIZE_INTEGRATIONS,
) -> SyncRun:
    require_operation_permission(
        actor,
        operation_permission,
        origin=origin,
        system=system,
    )
    if not integration.enabled:
        record_security_event(
            event_type="integration.sync_completed",
            origin=origin,
            outcome="denied",
            actor=actor,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"reason": "disabled"},
        )
        raise ValueError(f"Integration {integration.slug} is disabled")
    if SyncRun.objects.filter(
        integration=integration,
        status=SyncRun.Status.RUNNING,
    ).exists():
        record_security_event(
            event_type="integration.sync_completed",
            origin=origin,
            outcome="denied",
            actor=actor,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"reason": "already_running"},
        )
        raise ValueError(f"Integration {integration.slug} already has a running synchronization")

    run = SyncRun.objects.create(
        integration=integration,
        initiated_by=actor if getattr(actor, "is_authenticated", False) else None,
        origin=origin,
        cursor_before={},
    )
    record_security_event(
        event_type="integration.sync_started",
        origin=origin,
        outcome="started",
        actor=actor,
        target_type="integration",
        target_identifier=integration.pk,
        metadata={"sync_run_id": run.pk},
    )
    integration.last_attempt_at = timezone.now()
    integration.save(update_fields=["last_attempt_at", "updated_at"])

    current_cursor: Mapping[str, Any] = dict(integration.cursor)
    safe_cursor_before: Mapping[str, Any] = {}
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
        adapter = load_adapter(integration.adapter_path)
        context = _context(integration)
        validate_safe_cursor(current_cursor, resolved_secrets=context.secrets)
        safe_cursor_before = dict(current_cursor)
        run.cursor_before = dict(safe_cursor_before)
        run.save(update_fields=["cursor_before"])
        strict_records = bool(integration.configuration.get("strict_records", False))
        strict_projection = bool(
            integration.configuration.get("strict_projection", False)
        )
        project_records = bool(integration.configuration.get("project_records", True))
        configured_limit = int(
            integration.configuration.get(
                "max_batches_per_sync",
                getattr(settings, "THREATBRIDGE_MAX_PAGES_PER_SYNC", 50),
            )
        )
        max_batches = max(1, min(configured_limit, 1000))
        for batch_number in range(1, max_batches + 1):
            batch = adapter.pull(context, current_cursor)
            raw_records = list(batch.records)
            counters["received"] += len(raw_records)
            batch_metadata.append(
                {
                    **redacted_result(
                        batch.combined_metadata,
                        resolved_secrets=context.secrets,
                    ),
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

                should_project = not source_object.is_deleted and project_records and (
                    disposition != "unchanged"
                    or source_object.projection_status
                    in {
                        ExternalObject.ProjectionStatus.PENDING,
                        ExternalObject.ProjectionStatus.FAILED,
                    }
                )
                if should_project:
                    try:
                        projection_status, _projected = project_external_object(
                            source_object,
                            actor=actor,
                            origin=origin,
                            system=system,
                            operation_permission=operation_permission,
                        )
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
            validate_safe_cursor(next_cursor, resolved_secrets=context.secrets)
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
        record_security_event(
            event_type="integration.sync_completed",
            origin=origin,
            outcome=run.status,
            actor=actor,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={
                "sync_run_id": run.pk,
                "received": run.records_received,
                "accepted": run.records_accepted,
                "rejected": run.records_rejected,
                "projected": run.records_projected,
            },
        )
        return run
    except Exception as exc:
        safe_error = sanitized_connector_error(exc)
        run.status = SyncRun.Status.FAILED
        run.finished_at = timezone.now()
        run.cursor_after = dict(safe_cursor_before)
        run.records_received = counters["received"]
        run.records_accepted = counters["accepted"]
        run.records_rejected = counters["rejected"]
        run.records_created = counters["created"]
        run.records_updated = counters["updated"]
        run.records_unchanged = counters["unchanged"]
        run.records_projected = counters["projected"]
        run.projection_failures = counters["projection_failures"]
        run.error_summary = safe_error
        run.metadata = {"batches": batch_metadata, "bounded": bounded}
        run.save()
        integration.health = Integration.Health.ERROR
        integration.last_error = safe_error
        integration.save(update_fields=["health", "last_error", "updated_at"])
        record_security_event(
            event_type="integration.sync_completed",
            origin=origin,
            outcome="failed",
            actor=actor,
            target_type="integration",
            target_identifier=integration.pk,
            metadata={"sync_run_id": run.pk, "error_type": type(exc).__name__},
        )
        raise RuntimeError(safe_error) from None


def ingest_source_record(
    integration: Integration,
    record: SourceRecord,
    *,
    project: bool = True,
    actor=None,
    origin: str,
    system: bool = False,
) -> tuple[ExternalObject, str, str | None, Any | None]:
    """Store one already-normalized record, primarily for manual/API ingestion."""

    require_operation_permission(
        actor,
        Permissions.IMPORT_SOURCE_FILES,
        origin=origin,
        system=system,
    )

    with transaction.atomic():
        source_object, disposition = _store_record(integration, record)
    projection_status: str | None = None
    projected: Any | None = None
    if project and not source_object.is_deleted:
        projection_status, projected = project_external_object(
            source_object,
            actor=actor,
            origin=origin,
            system=system,
            operation_permission=Permissions.IMPORT_SOURCE_FILES,
        )
    return source_object, disposition, projection_status, projected
