from django.core.management.base import BaseCommand

from django_audit_log.models import LogUserAgent


class Command(BaseCommand):
    help = "Reprocess all user agents with current parsing logic"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to process in each batch (default: 1000)",
        )

    def handle(self, *args, **options):
        batch_size = options["batch_size"]

        self.stdout.write("Starting user agent reimport...")

        results = LogUserAgent.reimport_all(batch_size=batch_size)

        self.stdout.write(
            self.style.SUCCESS(
                f"\nReimport completed:\n"
                f"- Total agents processed: {results['total_agents']}\n"
                f"- Agents updated: {results['updated']}\n"
                f"- Agents unchanged: {results['total_agents'] - results['updated']}"
            )
        )
