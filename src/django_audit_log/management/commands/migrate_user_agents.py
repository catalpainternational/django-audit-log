from django.core.management.base import BaseCommand
from django.db import transaction

from django_audit_log.utils import get_user_agent_statistics, migrate_user_agents


class Command(BaseCommand):
    help = "Migrate existing user agent strings to the normalized LogUserAgent model"

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of user agents to process in each batch",
        )
        parser.add_argument(
            "--stats-only",
            action="store_true",
            help="Only show statistics without migrating",
        )

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        stats_only = options["stats_only"]

        # Get initial statistics
        initial_stats = get_user_agent_statistics()
        self.stdout.write(self.style.SUCCESS("Initial Statistics:"))
        self.stdout.write(f"Total logs: {initial_stats['total_logs']}")
        self.stdout.write(
            f"Normalized logs: {initial_stats['normalized_logs']} ({initial_stats['normalized_percentage']:.1f}%)"
        )
        self.stdout.write(
            f"Non-normalized logs: {initial_stats['non_normalized_logs']}"
        )
        self.stdout.write(f"Unique user agents: {initial_stats['unique_user_agents']}")

        if stats_only:
            self.stdout.write(self.style.SUCCESS("Stats-only mode, skipping migration"))
            return

        # Perform migration
        self.stdout.write(
            self.style.SUCCESS(f"Starting migration with batch size {batch_size}")
        )

        try:
            with transaction.atomic():
                results = migrate_user_agents(batch_size=batch_size)

                self.stdout.write(
                    self.style.SUCCESS("Migration completed successfully!")
                )
                self.stdout.write(f"Total agents processed: {results['total_agents']}")
                self.stdout.write(f"New agents created: {results['created_agents']}")
                self.stdout.write(f"Logs updated: {results['updated_logs']}")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error during migration: {str(e)}"))
            return

        # Get final statistics
        final_stats = get_user_agent_statistics()
        self.stdout.write(self.style.SUCCESS("Final Statistics:"))
        self.stdout.write(
            f"Normalized logs: {final_stats['normalized_logs']} ({final_stats['normalized_percentage']:.1f}%)"
        )
        self.stdout.write(f"Non-normalized logs: {final_stats['non_normalized_logs']}")
        self.stdout.write(f"Unique user agents: {final_stats['unique_user_agents']}")

        # Show top browsers
        self.stdout.write(self.style.SUCCESS("Top Browsers:"))
        for browser in final_stats["top_browsers"]:
            self.stdout.write(
                f"  {browser['browser'] or 'Unknown'}: {browser['count']}"
            )

        # Show top operating systems
        self.stdout.write(self.style.SUCCESS("Top Operating Systems:"))
        for os in final_stats["top_os"]:
            self.stdout.write(f"  {os['operating_system'] or 'Unknown'}: {os['count']}")

        # Show device types
        self.stdout.write(self.style.SUCCESS("Device Types:"))
        for device in final_stats["device_types"]:
            self.stdout.write(
                f"  {device['device_type'] or 'Unknown'}: {device['count']}"
            )

        # Show bot percentage
        self.stdout.write(
            self.style.SUCCESS(f"Bot traffic: {final_stats['bot_percentage']:.1f}%")
        )
