from __future__ import annotations

from typing import Any

from django.conf import settings
from django.utils.module_loading import import_string

from .adapters.base import IntegrationAdapter

BUILTIN_ADAPTERS = [
    "integrations.adapters.demo.DemoAdapter",
    "integrations.adapters.manual.ManualEntryAdapter",
    "integrations.adapters.csv_inventory.CsvInventoryAdapter",
    "integrations.adapters.json_file.JsonFileAdapter",
    "integrations.adapters.mitre_attack.MitreAttackStixAdapter",
    "integrations.adapters.defender_vm.DefenderVmAdapter",
    "integrations.adapters.opencti.OpenCtiReportsAdapter",
    "integrations.adapters.trivy.TrivyJsonAdapter",
]


def _allowed_prefixes() -> tuple[str, ...]:
    configured = getattr(
        settings,
        "THREATBRIDGE_ALLOWED_ADAPTER_PREFIXES",
        ("integrations.adapters.",),
    )
    if isinstance(configured, str):
        return tuple(part.strip() for part in configured.split(",") if part.strip())
    return tuple(configured)


def load_adapter(dotted_path: str) -> IntegrationAdapter:
    if not dotted_path or not any(dotted_path.startswith(prefix) for prefix in _allowed_prefixes()):
        raise ValueError(f"Adapter path is not allowed: {dotted_path}")
    adapter_class = import_string(dotted_path)
    adapter = adapter_class()
    if not isinstance(adapter, IntegrationAdapter):
        raise TypeError(f"{dotted_path} must extend IntegrationAdapter")
    return adapter


def available_adapters() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for dotted_path in BUILTIN_ADAPTERS:
        adapter = load_adapter(dotted_path)
        result.append(
            {
                "adapter_path": dotted_path,
                "adapter_key": adapter.adapter_key,
                "display_name": adapter.display_name,
                "description": adapter.description,
                "supported_object_types": list(adapter.supported_object_types),
                "configuration_example": dict(adapter.configuration_example),
                "configuration_schema": dict(adapter.configuration_schema),
            }
        )
    return result


adapter_catalog = available_adapters
