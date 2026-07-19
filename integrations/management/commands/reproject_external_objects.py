from django.core.management.base import BaseCommand

from integrations.models import ExternalObject
from integrations.services import project_external_object


class Command(BaseCommand):
    help = "Project stored external objects into ThreatBridge canonical models"

    def add_arguments(self, parser):
        parser.add_argument("--integration", help="Integration slug")
        parser.add_argument("--object-type", help="Normalized object type")
        parser.add_argument("--failed-only", action="store_true")

    def handle(self, *args, **options):
        queryset = ExternalObject.objects.select_related("integration").all()
        if options.get("integration"):
            queryset = queryset.filter(integration__slug=options["integration"])
        if options.get("object_type"):
            queryset = queryset.filter(object_type=options["object_type"])
        if options.get("failed_only"):
            queryset = queryset.filter(
                projection_status=ExternalObject.ProjectionStatus.FAILED
            )

        projected = skipped = failed = 0
        for source_object in queryset.iterator():
            try:
                status, _ = project_external_object(source_object)
                if status == ExternalObject.ProjectionStatus.PROJECTED:
                    projected += 1
                else:
                    skipped += 1
            except Exception as exc:
                failed += 1
                self.stderr.write(f"{source_object}: {exc}")

        self.stdout.write(
            self.style.SUCCESS(
                f"projected={projected} skipped={skipped} failed={failed}"
            )
        )
