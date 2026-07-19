from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone

from catalog.services.audit import record_security_event
from threatbridge.authorization import Permissions, require_permission

from .models import ExternalObject


@transaction.atomic
def delete_source_evidence(
    source_object: ExternalObject,
    *,
    actor: Any,
    reason: str,
    origin: str,
) -> ExternalObject:
    require_permission(actor, Permissions.DELETE_SOURCE_EVIDENCE)
    reason = str(reason).strip()
    if not reason:
        raise ValueError("A deletion reason is required.")
    locked = ExternalObject.objects.select_for_update().get(pk=source_object.pk)

    locked.is_deleted = True
    locked.deleted_at = timezone.now()
    locked.deleted_by = actor
    locked.deletion_reason = reason[:4000]
    locked.deletion_origin = str(origin)[:255]
    locked.save(
        update_fields=[
            "is_deleted",
            "deleted_at",
            "deleted_by",
            "deletion_reason",
            "deletion_origin",
            "last_seen_at",
        ]
    )
    record_security_event(
        event_type="source_evidence.deleted",
        origin=origin,
        outcome="succeeded",
        actor=actor,
        target_type="external_object",
        target_identifier=locked.pk,
        metadata={
            "integration_id": locked.integration_id,
            "object_type": locked.object_type,
        },
    )
    return locked


@transaction.atomic
def restore_source_evidence(
    source_object: ExternalObject,
    *,
    actor: Any,
    reason: str,
    origin: str,
) -> ExternalObject:
    require_permission(actor, Permissions.RESTORE_DELETED_SOURCE_EVIDENCE)
    reason = str(reason).strip()
    if not reason:
        raise ValueError("A restoration reason is required.")
    locked = ExternalObject.all_objects.select_for_update().get(pk=source_object.pk)
    if not locked.is_deleted:
        return locked

    locked.is_deleted = False
    locked.restored_at = timezone.now()
    locked.restored_by = actor
    locked.restoration_reason = reason[:4000]
    locked.restoration_origin = str(origin)[:255]
    locked.projection_status = ExternalObject.ProjectionStatus.PENDING
    locked.projection_error = ""
    locked.projected_at = None
    locked.save(
        update_fields=[
            "is_deleted",
            "restored_at",
            "restored_by",
            "restoration_reason",
            "restoration_origin",
            "projection_status",
            "projection_error",
            "projected_at",
            "last_seen_at",
        ]
    )
    record_security_event(
        event_type="source_evidence.restored",
        origin=origin,
        outcome="succeeded",
        actor=actor,
        target_type="external_object",
        target_identifier=locked.pk,
        metadata={
            "integration_id": locked.integration_id,
            "object_type": locked.object_type,
        },
    )
    return locked
