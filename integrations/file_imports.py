from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from .import_schemas import (
    integration_kind_for_object_type,
    suggest_field_map,
    suggest_id_fields,
    suggest_object_type,
)
from .models import Integration, SyncRun
from .services import run_integration_sync

ALLOWED_FILE_FORMATS = {
    ".csv": "csv",
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
}
COMMON_RECORD_KEYS = (
    "records",
    "items",
    "results",
    "objects",
    "reports",
    "assets",
    "devices",
    "findings",
    "vulnerabilities",
    "software",
    "detections",
    "rules",
    "tests",
    "data",
)
COMMON_RECORD_PARENTS = ("data", "response", "payload")


@dataclass(frozen=True)
class FileInspection:
    original_name: str
    file_format: str
    content_type: str
    size_bytes: int
    sha256: str
    encoding: str
    delimiter: str
    records_key: str
    record_count: int
    fields: list[str]
    sample_records: list[dict[str, Any]]
    suggested_object_type: str
    suggested_id_fields: list[str]
    suggested_field_map: dict[str, str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StoredUpload:
    relative_path: str
    absolute_path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class FileImportResult:
    integration: Integration
    run: SyncRun | None
    inspection: FileInspection
    stored_upload: StoredUpload


def _max_upload_bytes() -> int:
    return int(getattr(settings, "THREATBRIDGE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024))


def _max_import_records() -> int:
    return int(getattr(settings, "THREATBRIDGE_MAX_IMPORT_RECORDS", 100_000))


def _format_from_name(name: str) -> str:
    suffix = Path(name or "").suffix.lower()
    file_format = ALLOWED_FILE_FORMATS.get(suffix)
    if not file_format:
        allowed = ", ".join(sorted(ALLOWED_FILE_FORMATS))
        raise ValueError(f"Unsupported file extension. Accepted extensions: {allowed}.")
    return file_format


def _read_uploaded_bytes(uploaded_file: UploadedFile) -> bytes:
    declared_size = int(uploaded_file.size or 0)
    maximum = _max_upload_bytes()
    if declared_size > maximum:
        raise ValueError(f"File is too large. Maximum upload size is {maximum:,} bytes.")
    uploaded_file.seek(0)
    content = uploaded_file.read(maximum + 1)
    uploaded_file.seek(0)
    if len(content) > maximum:
        raise ValueError(f"File is too large. Maximum upload size is {maximum:,} bytes.")
    if not content:
        raise ValueError("The uploaded file is empty.")
    return content


def _decode_text(content: bytes, *, file_format: str) -> tuple[str, str]:
    try:
        return content.decode("utf-8-sig"), "utf-8-sig"
    except UnicodeDecodeError as exc:
        if file_format != "csv":
            raise ValueError("JSON and JSON Lines uploads must be UTF-8 encoded.") from exc
    try:
        return content.decode("cp1252"), "cp1252"
    except UnicodeDecodeError as exc:
        raise ValueError("CSV upload could not be decoded as UTF-8 or Windows-1252.") from exc


def _detect_delimiter(text: str, requested: str = "") -> str:
    if requested:
        if requested == "\\t":
            return "\t"
        if len(requested) != 1:
            raise ValueError("CSV delimiter must be one character.")
        return requested
    sample = text[:65_536]
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _navigate_records_key(payload: Any, records_key: str) -> Any:
    current = payload
    for segment in (part for part in records_key.split(".") if part):
        if isinstance(current, Mapping):
            if segment not in current:
                raise ValueError(f"JSON records key segment not found: {segment}")
            current = current[segment]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError) as exc:
                raise ValueError(f"JSON records key list index is invalid: {segment}") from exc
        else:
            raise ValueError(f"JSON records key cannot traverse segment: {segment}")
    return current


def _resolve_json_records(payload: Any, records_key: str) -> tuple[list[Mapping[str, Any]], str]:
    used_key = records_key.strip()
    resolved = _navigate_records_key(payload, used_key) if used_key else payload

    if not used_key and isinstance(resolved, Mapping):
        for key in COMMON_RECORD_KEYS:
            value = resolved.get(key)
            if isinstance(value, list):
                resolved = value
                used_key = key
                break
        else:
            for parent_key in COMMON_RECORD_PARENTS:
                parent = resolved.get(parent_key)
                if not isinstance(parent, Mapping):
                    continue
                for key in COMMON_RECORD_KEYS:
                    value = parent.get(key)
                    if isinstance(value, list):
                        resolved = value
                        used_key = f"{parent_key}.{key}"
                        break
                if used_key:
                    break

    if isinstance(resolved, Mapping):
        records: list[Any] = [resolved]
    elif isinstance(resolved, list):
        records = resolved
    else:
        raise ValueError("JSON payload must resolve to an object or an array of objects.")

    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise ValueError(f"JSON record {index} is not an object.")
    return [dict(record) for record in records], used_key


def _inspect_csv(
    text: str,
    *,
    requested_delimiter: str = "",
) -> tuple[list[str], list[dict[str, Any]], int, str]:
    delimiter = _detect_delimiter(text, requested_delimiter)
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    if not reader.fieldnames:
        raise ValueError("CSV upload does not contain a header row.")
    fields = [str(field or "").strip() for field in reader.fieldnames]
    if any(not field for field in fields):
        raise ValueError("CSV header contains an empty column name.")
    normalized = [field.casefold() for field in fields]
    if len(normalized) != len(set(normalized)):
        raise ValueError("CSV header contains duplicate column names.")

    samples: list[dict[str, Any]] = []
    record_count = 0
    maximum = _max_import_records()
    for row in reader:
        if row is None or not any(value not in (None, "") for value in row.values()):
            continue
        record_count += 1
        if record_count > maximum:
            raise ValueError(f"Import contains more than the {maximum:,}-record limit.")
        if len(samples) < 5:
            samples.append({str(key): value for key, value in row.items()})
    if record_count == 0:
        raise ValueError("CSV upload contains no data rows.")
    return fields, samples, record_count, delimiter


def _inspect_json(
    text: str,
    *,
    file_format: str,
    records_key: str,
) -> tuple[list[str], list[dict[str, Any]], int, str]:
    if file_format == "jsonl":
        records: list[dict[str, Any]] = []
        maximum = _max_import_records()
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON Lines record {line_number} is invalid: {exc.msg}.") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"JSON Lines record {line_number} is not an object.")
            records.append(dict(value))
            if len(records) > maximum:
                raise ValueError(f"Import contains more than the {maximum:,}-record limit.")
        used_key = ""
    else:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"JSON is invalid at line {exc.lineno}, column {exc.colno}: {exc.msg}."
            ) from exc
        records, used_key = _resolve_json_records(payload, records_key)
        maximum = _max_import_records()
        if len(records) > maximum:
            raise ValueError(f"Import contains more than the {maximum:,}-record limit.")

    if not records:
        raise ValueError("JSON upload contains no records.")
    field_set: set[str] = set()
    for record in records[:500]:
        field_set.update(_json_field_paths(record))
    fields = sorted(field_set, key=lambda value: value.casefold())
    return fields, records[:5], len(records), used_key


def _json_field_paths(
    record: Mapping[str, Any],
    *,
    prefix: str = "",
    depth: int = 0,
    max_depth: int = 6,
) -> set[str]:
    """Return dotted source paths for JSON preview and mapping suggestions.

    Lists remain a single field because canonical values such as techniques,
    vulnerabilities, and observables intentionally accept array values.
    """

    paths: set[str] = set()
    for key, value in record.items():
        key_text = str(key)
        path = f"{prefix}.{key_text}" if prefix else key_text
        if isinstance(value, Mapping) and value and depth < max_depth:
            paths.update(
                _json_field_paths(
                    value,
                    prefix=path,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
            )
        else:
            paths.add(path)
    return paths


def inspect_uploaded_file(
    uploaded_file: UploadedFile,
    *,
    records_key: str = "",
    delimiter: str = "",
    object_type: str = "auto",
) -> FileInspection:
    file_format = _format_from_name(uploaded_file.name)
    content = _read_uploaded_bytes(uploaded_file)
    text, encoding = _decode_text(content, file_format=file_format)

    if file_format == "csv":
        fields, samples, record_count, detected_delimiter = _inspect_csv(
            text,
            requested_delimiter=delimiter,
        )
        used_key = ""
    else:
        fields, samples, record_count, used_key = _inspect_json(
            text,
            file_format=file_format,
            records_key=records_key,
        )
        detected_delimiter = ""

    suggested_type = (
        suggest_object_type(fields, samples[0] if samples else None)
        if object_type in {"", "auto"}
        else object_type
    )
    if file_format == "csv" and suggested_type == "mixed":
        suggested_type = "asset"
    return FileInspection(
        original_name=Path(uploaded_file.name).name,
        file_format=file_format,
        content_type=str(uploaded_file.content_type or "application/octet-stream"),
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        encoding=encoding,
        delimiter=detected_delimiter,
        records_key=used_key,
        record_count=record_count,
        fields=fields,
        sample_records=samples,
        suggested_object_type=suggested_type,
        suggested_id_fields=suggest_id_fields(fields, suggested_type),
        suggested_field_map=suggest_field_map(fields, suggested_type),
    )


def _upload_destination(original_name: str) -> tuple[Path, str]:
    suffix = Path(original_name).suffix.lower()
    _format_from_name(original_name)
    base = Path(settings.THREATBRIDGE_DATA_DIR).resolve()
    date_path = timezone.localdate().strftime("%Y/%m/%d")
    relative = Path("incoming") / "uploads" / date_path / f"{uuid.uuid4().hex}{suffix}"
    destination = (base / relative).resolve()
    if base not in destination.parents:
        raise ValueError("Upload destination escaped the configured data directory.")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    return destination, relative.as_posix()


def store_uploaded_file(uploaded_file: UploadedFile) -> StoredUpload:
    destination, relative_path = _upload_destination(uploaded_file.name)
    maximum = _max_upload_bytes()
    digest = hashlib.sha256()
    size = 0
    uploaded_file.seek(0)
    try:
        with destination.open("xb") as handle:
            for chunk in uploaded_file.chunks():
                size += len(chunk)
                if size > maximum:
                    raise ValueError(
                        f"File is too large. Maximum upload size is {maximum:,} bytes."
                    )
                digest.update(chunk)
                handle.write(chunk)
        os.chmod(destination, 0o600)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        uploaded_file.seek(0)
    return StoredUpload(
        relative_path=relative_path,
        absolute_path=destination,
        sha256=digest.hexdigest(),
        size_bytes=size,
    )


def _unique_slug(name: str, existing: Integration | None = None) -> str:
    base = slugify(name)[:45] or "file-import"
    candidate = base
    number = 2
    queryset = Integration.objects.all()
    if existing is not None:
        queryset = queryset.exclude(pk=existing.pk)
    while queryset.filter(slug=candidate).exists():
        suffix = f"-{number}"
        candidate = f"{base[: 50 - len(suffix)]}{suffix}"
        number += 1
    return candidate


def _clean_id_fields(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = value
    result: list[str] = []
    for item in values:
        field = str(item).strip()
        if field and field not in result:
            result.append(field)
    return result


def create_file_import(
    *,
    uploaded_file: UploadedFile,
    name: str = "",
    object_type: str = "auto",
    id_fields: Iterable[str] | str | None = None,
    records_key: str = "",
    natural_key_field: str = "",
    updated_at_field: str = "",
    field_map: Mapping[str, str] | None = None,
    delimiter: str = "",
    default_review_status: str = "pending",
    strict_records: bool = False,
    sync_now: bool = True,
    integration: Integration | None = None,
) -> FileImportResult:
    existing_configuration = dict(integration.configuration) if integration else {}
    if integration:
        if object_type in {"", "auto"}:
            object_type = (
                "mixed"
                if existing_configuration.get("envelope")
                else str(existing_configuration.get("object_type") or "auto")
            )
        if not _clean_id_fields(id_fields):
            id_fields = existing_configuration.get("id_fields") or existing_configuration.get(
                "id_field"
            )
        if not records_key:
            records_key = str(existing_configuration.get("records_key", ""))
        if not natural_key_field:
            natural_key_field = str(existing_configuration.get("natural_key_field", ""))
        if not updated_at_field:
            updated_at_field = str(existing_configuration.get("updated_at_field", ""))
        if not field_map:
            stored_map = existing_configuration.get("field_map", {})
            field_map = stored_map if isinstance(stored_map, Mapping) else {}
        if not delimiter:
            delimiter = str(existing_configuration.get("delimiter", ""))
        if default_review_status == "pending":
            default_review_status = str(
                existing_configuration.get("default_review_status", default_review_status)
            )
        strict_records = bool(strict_records or existing_configuration.get("strict_records", False))
        name = name or integration.name

    requested_type = object_type or "auto"
    inspection = inspect_uploaded_file(
        uploaded_file,
        records_key=records_key,
        delimiter=delimiter,
        object_type=requested_type,
    )
    resolved_type = inspection.suggested_object_type if requested_type == "auto" else requested_type
    if resolved_type == "mixed" and inspection.file_format == "csv":
        raise ValueError("Mixed-object imports require JSON or JSON Lines format.")

    resolved_id_fields = _clean_id_fields(id_fields)
    if not resolved_id_fields:
        resolved_id_fields = inspection.suggested_id_fields
    if resolved_type != "mixed" and not resolved_id_fields:
        raise ValueError(
            "No stable record identifier could be inferred. Provide one or more ID fields."
        )

    resolved_map = dict(field_map or {})
    if not resolved_map:
        resolved_map = inspection.suggested_field_map
    invalid_map = [
        key for key, value in resolved_map.items() if not str(key).strip() or not str(value).strip()
    ]
    if invalid_map:
        raise ValueError("Field-map keys and values must be non-empty strings.")

    stored = store_uploaded_file(uploaded_file)
    display_name = name.strip() or f"{Path(inspection.original_name).stem} import"
    adapter_path = (
        "integrations.adapters.csv_inventory.CsvInventoryAdapter"
        if inspection.file_format == "csv"
        else "integrations.adapters.json_file.JsonFileAdapter"
    )
    configuration: dict[str, Any] = {
        "path": stored.relative_path,
        "format": inspection.file_format,
        "encoding": inspection.encoding,
        "skip_unchanged": True,
        "project_records": True,
        "strict_records": bool(strict_records),
        "passthrough_unmapped": True,
        "max_records": _max_import_records(),
        "field_map": resolved_map,
        "natural_key_field": natural_key_field.strip(),
        "updated_at_field": updated_at_field.strip(),
        "default_review_status": default_review_status,
        "upload": {
            "original_name": inspection.original_name,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "record_count": inspection.record_count,
            "uploaded_at": timezone.now().isoformat(),
            "fields": inspection.fields,
        },
    }
    if inspection.file_format == "csv":
        configuration.update(
            {
                "delimiter": inspection.delimiter,
                "object_type": resolved_type,
                "id_fields": resolved_id_fields,
            }
        )
    else:
        configuration["records_key"] = records_key.strip() or inspection.records_key
        if resolved_type == "mixed":
            configuration["envelope"] = True
        else:
            configuration.update(
                {
                    "object_type": resolved_type,
                    "id_fields": resolved_id_fields,
                    "id_field": resolved_id_fields[0],
                }
            )

    try:
        with transaction.atomic():
            if integration is None:
                integration = Integration.objects.create(
                    name=display_name,
                    slug=_unique_slug(display_name),
                    kind=integration_kind_for_object_type(resolved_type),
                    adapter_path=adapter_path,
                    enabled=True,
                    configuration=configuration,
                )
            else:
                integration.name = display_name or integration.name
                integration.slug = _unique_slug(integration.slug or integration.name, integration)
                integration.kind = integration_kind_for_object_type(resolved_type)
                integration.adapter_path = adapter_path
                integration.enabled = True
                integration.configuration = configuration
                integration.cursor = {}
                integration.health = Integration.Health.UNKNOWN
                integration.last_error = ""
                integration.save()
    except Exception:
        stored.absolute_path.unlink(missing_ok=True)
        raise

    run = run_integration_sync(integration) if sync_now else None
    return FileImportResult(
        integration=integration,
        run=run,
        inspection=inspection,
        stored_upload=stored,
    )
