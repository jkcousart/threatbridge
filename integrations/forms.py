from __future__ import annotations

from django import forms
from django.conf import settings

from .import_schemas import IMPORT_OBJECT_TYPE_CHOICES
from .models import Integration

FILE_ADAPTER_PATHS = (
    "integrations.adapters.csv_inventory.CsvInventoryAdapter",
    "integrations.adapters.json_file.JsonFileAdapter",
)


class FileImportForm(forms.Form):
    file = forms.FileField(
        label="CSV or JSON file",
        help_text="Accepted: .csv, .json, .jsonl, and .ndjson.",
        widget=forms.ClearableFileInput(attrs={"accept": ".csv,.json,.jsonl,.ndjson"}),
    )
    integration = forms.ModelChoiceField(
        label="Existing import profile",
        required=False,
        queryset=Integration.objects.none(),
        help_text=(
            "Optional. Selecting a profile replaces its source file and retains "
            "its identity."
        ),
    )
    name = forms.CharField(
        label="Import profile name",
        max_length=200,
        required=False,
        help_text="A reusable integration profile is created when this is left blank.",
    )
    object_type = forms.ChoiceField(
        choices=IMPORT_OBJECT_TYPE_CHOICES,
        initial="auto",
        help_text="Use mixed-object mode for ThreatBridge envelope JSON.",
    )
    id_fields = forms.CharField(
        label="Stable ID field(s)",
        required=False,
        help_text="Comma-separated. Composite IDs are supported, for example device_id,cve_id.",
    )
    records_key = forms.CharField(
        required=False,
        help_text="Optional dotted path to a JSON array, for example data.results.",
    )
    natural_key_field = forms.CharField(required=False)
    updated_at_field = forms.CharField(required=False)
    delimiter = forms.CharField(
        required=False,
        max_length=2,
        help_text="CSV only. Leave blank for automatic detection. Use \\t for a tab.",
    )
    field_map = forms.JSONField(
        required=False,
        initial=dict,
        help_text=(
            'Maps source fields to ThreatBridge fields, for example '
            '{"deviceId":"asset_external_id"}.'
        ),
        widget=forms.Textarea(
            attrs={
                "rows": 12,
                "spellcheck": "false",
                "placeholder": (
                    '{\n  "deviceId": "asset_external_id",\n'
                    '  "deviceName": "hostname"\n}'
                ),
            }
        ),
    )
    default_review_status = forms.ChoiceField(
        choices=(
            ("pending", "Pending analyst review"),
            ("approved", "Approved on import"),
            ("uncertain", "Uncertain"),
        ),
        initial="pending",
        help_text="Applied to ATT&CK mappings embedded in imported threat reports.",
    )
    strict_records = forms.BooleanField(
        required=False,
        help_text="Stop the entire synchronization when any record is invalid.",
    )
    sync_now = forms.BooleanField(
        required=False,
        initial=True,
        help_text="Immediately normalize and project records after upload.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["integration"].queryset = Integration.objects.filter(
            adapter_path__in=FILE_ADAPTER_PATHS
        ).order_by("name")

    def clean_file(self):
        uploaded_file = self.cleaned_data["file"]
        maximum = int(
            getattr(settings, "THREATBRIDGE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)
        )
        if uploaded_file.size and uploaded_file.size > maximum:
            raise forms.ValidationError(
                f"File exceeds the configured {maximum:,}-byte upload limit."
            )
        suffix = uploaded_file.name.lower().rsplit(".", 1)[-1]
        if suffix not in {"csv", "json", "jsonl", "ndjson"}:
            raise forms.ValidationError("Upload a .csv, .json, .jsonl, or .ndjson file.")
        return uploaded_file

    def clean_field_map(self):
        value = self.cleaned_data.get("field_map") or {}
        if not isinstance(value, dict):
            raise forms.ValidationError("Field map must be a JSON object.")
        return {str(key): str(destination) for key, destination in value.items()}
