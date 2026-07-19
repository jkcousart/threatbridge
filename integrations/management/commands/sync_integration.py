from django.core.management.base import BaseCommand, CommandError

from integrations.models import Integration
from integrations.secrets import sanitized_connector_error
from integrations.services import run_integration_sync


class Command(BaseCommand):
    help = "Synchronize one configured ThreatBridge integration"

    def add_arguments(self, parser):
        parser.add_argument("slug")

    def handle(self, *args, **options):
        try:
            integration = Integration.objects.get(slug=options["slug"])
            run = run_integration_sync(
                integration,
                origin="management:sync_integration",
                system=True,
            )
        except Integration.DoesNotExist as exc:
            raise CommandError(f"Unknown integration: {options['slug']}") from exc
        except Exception as exc:
            raise CommandError(sanitized_connector_error(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"{integration.slug}: status={run.status} batches={run.batches_processed} "
                f"received={run.records_received} accepted={run.records_accepted} "
                f"rejected={run.records_rejected} projected={run.records_projected}"
            )
        )
