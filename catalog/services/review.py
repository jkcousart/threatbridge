from __future__ import annotations

from typing import Any

from django.db import transaction

from catalog.models import AttackMappingReviewEvent, ThreatReportTechnique
from catalog.services.audit import record_security_event
from integrations.models import ExternalObject
from threatbridge.authorization import Permissions, require_permission

REVIEW_DECISIONS = {
    ThreatReportTechnique.ReviewStatus.APPROVED,
    ThreatReportTechnique.ReviewStatus.REJECTED,
}


@transaction.atomic
def transition_attack_mapping_review(
    mapping: ThreatReportTechnique,
    *,
    new_state: str,
    actor: Any,
    reason: str,
    origin: str,
) -> ThreatReportTechnique:
    require_permission(actor, Permissions.REVIEW_ATTACK_MAPPINGS)
    if new_state not in REVIEW_DECISIONS:
        raise ValueError("ATT&CK mappings may only be approved or rejected by review.")
    reason = str(reason).strip()
    if not reason:
        raise ValueError("An analyst review note is required.")

    locked = (
        ThreatReportTechnique.objects.select_for_update()
        .select_related("report__source_object", "technique")
        .get(pk=mapping.pk)
    )
    report_source = ExternalObject.all_objects.select_for_update().get(
        pk=locked.report.source_object_id
    )
    if report_source.is_deleted:
        raise ValueError("Deleted report evidence cannot be reviewed.")
    locked.report.source_object = report_source
    previous_state = locked.review_status
    if previous_state == new_state:
        return locked

    locked.review_status = new_state
    locked.save(update_fields=["review_status", "updated_at"])
    AttackMappingReviewEvent.objects.create(
        mapping=locked,
        mapping_identifier=str(locked.pk),
        previous_state=previous_state,
        new_state=new_state,
        actor=actor,
        actor_label=str(actor.get_username() or actor.pk)[:255],
        reason=reason[:4000],
        origin=str(origin)[:255],
    )
    record_security_event(
        event_type="attack_mapping.reviewed",
        origin=origin,
        outcome="succeeded",
        actor=actor,
        target_type="attack_mapping",
        target_identifier=locked.pk,
        metadata={
            "previous_state": previous_state,
            "new_state": new_state,
            "report_id": locked.report_id,
            "technique_id": locked.technique.technique_id,
        },
    )
    return locked
