# Generated for ThreatBridge Phase 1 application hardening.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

import integrations.models


class Migration(migrations.Migration):
    dependencies = [
        ("integrations", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterModelManagers(
            name="externalobject",
            managers=[
                ("objects", integrations.models.ActiveExternalObjectManager()),
                ("all_objects", models.Manager()),
            ],
        ),
        migrations.AlterModelOptions(
            name="integration",
            options={
                "ordering": ["name"],
                "permissions": [
                    ("configure_integration", "Can configure integrations"),
                    ("test_integration", "Can test integrations"),
                    ("synchronize_integration", "Can synchronize integrations"),
                    ("import_source_file", "Can import local source files"),
                ],
            },
        ),
        migrations.AlterModelOptions(
            name="externalobject",
            options={
                "base_manager_name": "all_objects",
                "default_manager_name": "objects",
                "permissions": [
                    (
                        "view_restricted_source_evidence",
                        "Can view restricted source evidence",
                    ),
                    ("view_deleted_source_evidence", "Can view deleted source evidence"),
                    ("delete_source_evidence", "Can delete source evidence"),
                    (
                        "restore_deleted_source_evidence",
                        "Can restore deleted source evidence",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="syncrun",
            name="initiated_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="threatbridge_sync_runs",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="syncrun",
            name="origin",
            field=models.CharField(default="unknown", max_length=255),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="deleted_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="deleted_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="threatbridge_deleted_evidence",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="deletion_origin",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="deletion_reason",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="restored_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="restored_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="threatbridge_restored_evidence",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="restoration_origin",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="externalobject",
            name="restoration_reason",
            field=models.TextField(blank=True),
        ),
    ]
