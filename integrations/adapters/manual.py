from collections.abc import Mapping
from typing import Any

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext


class ManualEntryAdapter(IntegrationAdapter):
    adapter_key = "manual-entry"
    display_name = "Manual entry"
    description = (
        "Internal placeholder for records entered through the ThreatBridge API "
        "or user interface."
    )
    supported_object_types = ("threat_report", "detection_rule", "validation_result")

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        return {"ok": True, "mode": "manual"}

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        return PullBatch(records=[], next_cursor={"complete": True}, complete=True)

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        raise NotImplementedError("Manual records are already normalized before storage")
