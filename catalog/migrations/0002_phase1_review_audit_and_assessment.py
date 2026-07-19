# Generated for ThreatBridge Phase 1 application hardening.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("catalog", "0001_initial"),
        ("integrations", "0002_phase1_authorization_and_evidence"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="assessment",
            options={
                "ordering": ["-started_at"],
                "permissions": [
                    ("run_assessment", "Can run or recalculate assessments"),
                ],
            },
        ),
        migrations.AlterModelOptions(
            name="threatreporttechnique",
            options={
                "permissions": [
                    (
                        "review_attack_mapping",
                        "Can approve or reject ATT&CK mappings",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="assessment",
            name="origin",
            field=models.CharField(default="unknown", max_length=255),
        ),
        migrations.AddField(
            model_name="assessment",
            name="evidence_sources",
            field=models.ManyToManyField(
                blank=True,
                related_name="assessments",
                to="integrations.externalobject",
            ),
        ),
        migrations.AddField(
            model_name="assessment",
            name="evidence_provenance_complete",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="AttackMappingReviewEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("mapping_identifier", models.CharField(max_length=64)),
                (
                    "previous_state",
                    models.CharField(
                        choices=[
                            ("approved", "Approved"),
                            ("pending", "Pending"),
                            ("rejected", "Rejected"),
                            ("uncertain", "Uncertain"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "new_state",
                    models.CharField(
                        choices=[
                            ("approved", "Approved"),
                            ("pending", "Pending"),
                            ("rejected", "Rejected"),
                            ("uncertain", "Uncertain"),
                        ],
                        max_length=16,
                    ),
                ),
                ("actor_label", models.CharField(blank=True, max_length=255)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("reason", models.TextField(blank=True)),
                ("origin", models.CharField(max_length=255)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="threatbridge_mapping_reviews",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "mapping",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="review_events",
                        to="catalog.threatreporttechnique",
                    ),
                ),
            ],
            options={"ordering": ["-timestamp", "-id"]},
        ),
        migrations.CreateModel(
            name="SecurityAuditEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("actor_label", models.CharField(blank=True, max_length=255)),
                ("origin", models.CharField(max_length=255)),
                ("event_type", models.CharField(max_length=100)),
                ("target_type", models.CharField(blank=True, max_length=100)),
                ("target_identifier", models.CharField(blank=True, max_length=255)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("outcome", models.CharField(max_length=32)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="threatbridge_security_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp", "-id"],
                "permissions": [
                    (
                        "administer_security_configuration",
                        "Can administer ThreatBridge security configuration",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="VulnerabilitySource",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "source_object",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="vulnerability_projections",
                        to="integrations.externalobject",
                    ),
                ),
                (
                    "vulnerability",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="sources",
                        to="catalog.vulnerability",
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="vulnerabilitysource",
            constraint=models.UniqueConstraint(
                fields=("source_object", "vulnerability"),
                name="catalog_unique_vulnerability_source",
            ),
        ),
    ]
