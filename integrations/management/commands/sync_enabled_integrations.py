from django.core.management.base import BaseCommand

from integrations.models import Integration
from integrations.services import run_integration_sync


class Command(BaseCommand):
    help = "Synchronize all enabled ThreatBridge integrations"

    def handle(self, *args, **options):
        failures = 0
        for integration in Integration.objects.filter(enabled=True):
            try:
                run = run_integration_sync(integration)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"{integration.slug}: {run.status}; accepted={run.records_accepted}; "
                        f"rejected={run.records_rejected}"
                    )
                )
            except Exception as exc:
                failures += 1
                self.stderr.write(self.style.ERROR(f"{integration.slug}: {exc}"))
        if failures:
            self.stderr.write(self.style.WARNING(f"{failures} integration(s) failed"))
