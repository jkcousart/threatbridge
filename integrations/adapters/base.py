from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SyncContext:
    integration_slug: str
    configuration: Mapping[str, Any]
    secret_reference: str
    secrets: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class SourceRecord:
    """One vendor record expressed in ThreatBridge's stable envelope."""

    external_id: str
    object_type: str
    raw: Mapping[str, Any]
    normalized: Mapping[str, Any]
    natural_key: str = ""
    source_updated_at: datetime | None = None


@dataclass(frozen=True)
class PullBatch:
    """A page, export fragment, or complete snapshot returned by an adapter.

    ``complete``/``metadata`` are the preferred fields. ``has_more`` and the
    ``source_*`` fields remain supported so adapters can expose vendor paging
    semantics without being rewritten.
    """

    records: Iterable[Mapping[str, Any]]
    next_cursor: Mapping[str, Any] = field(default_factory=dict)
    complete: bool | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    has_more: bool | None = None
    snapshot_complete: bool = False
    source_metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_complete(self) -> bool:
        if self.complete is not None:
            return self.complete
        if self.has_more is not None:
            return not self.has_more
        return self.snapshot_complete

    @property
    def combined_metadata(self) -> dict[str, Any]:
        return {**dict(self.source_metadata), **dict(self.metadata)}


class IntegrationAdapter:
    """Read-only vendor connector contract.

    Adapters pull vendor records, normalize each one into ThreatBridge's stable
    object schemas, and return a cursor that is only committed after the batch
    has been stored successfully.
    """

    adapter_key = "custom"
    display_name = "Custom integration"
    description = ""
    configuration_example: Mapping[str, Any] = {}
    configuration_schema: Mapping[str, Any] = {}
    supported_object_types: tuple[str, ...] = ()

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        raise NotImplementedError

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        raise NotImplementedError

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        raise NotImplementedError
