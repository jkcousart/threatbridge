from django.core.management.base import BaseCommand, CommandError

from catalog.models import Assessment, ThreatReport
from catalog.services.assess import generate_assessment
from integrations.models import Integration
from integrations.services import run_integration_sync


class Command(BaseCommand):
    help = "Create and synchronize the credential-free ThreatBridge demonstration scenario"

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-assessment",
            action="store_true",
            help="Import the demo records without generating an assessment.",
        )

    def handle(self, *args, **options):
        integration, created = Integration.objects.update_or_create(
            slug="demo-scenario",
            defaults={
                "name": "ThreatBridge demo scenario",
                "kind": Integration.Kind.GENERIC,
                "adapter_path": "integrations.adapters.demo.DemoAdapter",
                "enabled": True,
                "configuration": {
                    "default_review_status": "approved",
                    "project_records": True,
                },
            },
        )
        try:
            run = run_integration_sync(integration)
        except Exception as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"{'Created' if created else 'Updated'} {integration.slug}; "
                f"sync={run.status}; received={run.records_received}; "
                f"projected={run.records_projected}."
            )
        )

        if options["no_assessment"]:
            return

        try:
            report = ThreatReport.objects.get(
                integration=integration,
                external_id="report-healthcare-demo-campaign",
            )
        except ThreatReport.DoesNotExist as exc:
            raise CommandError("The demo threat report was not projected.") from exc

        assessment = generate_assessment(report)
        if assessment.status != Assessment.Status.SUCCEEDED:
            raise CommandError(assessment.error_summary or "Demo assessment failed")
        self.stdout.write(
            self.style.SUCCESS(
                f"Assessment {assessment.id}: "
                f"findings={assessment.summary.get('finding_count', 0)}; "
                f"highest_priority={assessment.summary.get('highest_priority', 'info')}."
            )
        )
