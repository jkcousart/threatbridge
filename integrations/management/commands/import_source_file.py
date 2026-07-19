from __future__ import annotations

import json
import mimetypes
from pathlib import Path
from typing import Any

from django.core.files.uploadedfile import UploadedFile
from django.core.management.base import BaseCommand, CommandError

from integrations.file_imports import create_file_import
from integrations.import_schemas import IMPORT_OBJECT_TYPE_CHOICES
from integrations.models import Integration
from integrations.secrets import sanitized_connector_error


class Command(BaseCommand):
    help = "Import a CSV, JSON, JSONL, or NDJSON source file into ThreatBridge"

    def add_arguments(self, parser):
        parser.add_argument("path", help="Path to a .csv, .json, .jsonl, or .ndjson file")
        parser.add_argument("--name", default="", help="Reusable import profile name")
        parser.add_argument(
            "--profile",
            default="",
            help="Refresh an existing file-import profile by integration slug",
        )
        parser.add_argument(
            "--object-type",
            choices=[value for value, _label in IMPORT_OBJECT_TYPE_CHOICES],
            default="auto",
        )
        parser.add_argument(
            "--id-fields",
            default="",
            help="Comma-separated stable ID fields; composite identifiers are supported",
        )
        parser.add_argument(
            "--records-key",
            default="",
            help="Dotted path to the JSON record array, for example data.results",
        )
        parser.add_argument("--natural-key-field", default="")
        parser.add_argument("--updated-at-field", default="")
        parser.add_argument(
            "--field-map",
            default="",
            help=(
                "JSON object mapping source fields to canonical fields, or @path/to/map.json"
            ),
        )
        parser.add_argument(
            "--delimiter",
            default="",
            help="CSV delimiter. Leave blank to auto-detect; use \\t for a tab",
        )
        parser.add_argument("--strict-records", action="store_true")
        parser.add_argument(
            "--no-sync",
            action="store_true",
            help="Create or refresh the profile without immediately importing records",
        )

    @staticmethod
    def _field_map(value: str) -> dict[str, str]:
        if not value:
            return {}
        source = value
        if value.startswith("@"):
            path = Path(value[1:]).expanduser().resolve()
            if not path.is_file():
                raise CommandError(f"Field-map file does not exist: {path}")
            source = path.read_text(encoding="utf-8")
        try:
            payload: Any = json.loads(source)
        except json.JSONDecodeError as exc:
            raise CommandError(f"Field map is not valid JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise CommandError("Field map must be a JSON object")
        return {str(key): str(destination) for key, destination in payload.items()}

    @staticmethod
    def _profile(slug: str) -> Integration | None:
        if not slug:
            return None
        try:
            return Integration.objects.get(slug=slug)
        except Integration.DoesNotExist as exc:
            raise CommandError(f"Unknown integration profile: {slug}") from exc

    def handle(self, *args, **options):
        path = Path(options["path"]).expanduser().resolve()
        if not path.is_file():
            raise CommandError(f"Source file does not exist: {path}")

        try:
            with path.open("rb") as handle:
                upload = UploadedFile(
                    file=handle,
                    name=path.name,
                    content_type=mimetypes.guess_type(path.name)[0]
                    or "application/octet-stream",
                    size=path.stat().st_size,
                )
                result = create_file_import(
                    uploaded_file=upload,
                    name=options["name"],
                    object_type=options["object_type"],
                    id_fields=options["id_fields"],
                    records_key=options["records_key"],
                    natural_key_field=options["natural_key_field"],
                    updated_at_field=options["updated_at_field"],
                    field_map=self._field_map(options["field_map"]),
                    delimiter=options["delimiter"],
                    strict_records=options["strict_records"],
                    sync_now=not options["no_sync"],
                    integration=self._profile(options["profile"]),
                    origin="management:import_source_file",
                    system=True,
                )
        except CommandError:
            raise
        except Exception as exc:
            raise CommandError(sanitized_connector_error(exc)) from exc

        inspection = result.inspection
        self.stdout.write(
            self.style.SUCCESS(
                f"profile={result.integration.slug} format={inspection.file_format} "
                f"type={inspection.suggested_object_type} records={inspection.record_count} "
                f"sha256={result.stored_upload.sha256}"
            )
        )
        if result.run is not None:
            self.stdout.write(
                self.style.SUCCESS(
                    f"sync={result.run.status} received={result.run.records_received} "
                    f"accepted={result.run.records_accepted} "
                    f"rejected={result.run.records_rejected} "
                    f"projected={result.run.records_projected}"
                )
            )
