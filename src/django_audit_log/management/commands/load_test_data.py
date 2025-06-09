import random
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from django_audit_log.models import (
    AccessLog,
    LogIpAddress,
    LogPath,
    LogSessionKey,
    LogUser,
    LogUserAgent,
)

User = get_user_model()


class Command(BaseCommand):
    help = "Load test data for Django Audit Log"

    def add_arguments(self, parser):
        parser.add_argument(
            "--urls",
            type=int,
            default=10,
            help="Number of unique URLs to create (default: 10)",
        )
        parser.add_argument(
            "--audit-logs",
            type=int,
            default=10000,
            help="Number of audit log entries to create (default: 10000)",
        )
        parser.add_argument(
            "--users",
            type=int,
            default=5,
            help="Number of regular users to create (default: 5)",
        )
        parser.add_argument(
            "--admin-users",
            type=int,
            default=1,
            help="Number of admin users to create (default: 1)",
        )
        parser.add_argument(
            "--clean",
            action="store_true",
            help="Delete existing test data before creating new data",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Batch size for creating audit logs (default: 500)",
        )

    def handle(self, *args, **options):
        urls_count = options["urls"]
        audit_logs_count = options["audit_logs"]
        users_count = options["users"]
        admin_users_count = options["admin_users"]
        clean = options["clean"]
        batch_size = options["batch_size"]

        if clean:
            self.stdout.write(self.style.WARNING("Cleaning existing test data..."))
            self._clean_test_data()

        self.stdout.write(self.style.SUCCESS("Starting test data creation..."))

        try:
            with transaction.atomic():
                # Create users first (they're referenced by audit logs)
                users = self._create_users(users_count, admin_users_count)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Created {len(users)} users ({admin_users_count} admins, {users_count} regular)"
                    )
                )

                # Create common paths
                paths = self._create_paths(urls_count)
                self.stdout.write(self.style.SUCCESS(f"Created {len(paths)} URL paths"))

                # Create user agents
                user_agents = self._create_user_agents()
                self.stdout.write(
                    self.style.SUCCESS(f"Created {len(user_agents)} user agents")
                )

                # Create IP addresses
                ip_addresses = self._create_ip_addresses()
                self.stdout.write(
                    self.style.SUCCESS(f"Created {len(ip_addresses)} IP addresses")
                )

                # Create session keys
                session_keys = self._create_session_keys()
                self.stdout.write(
                    self.style.SUCCESS(f"Created {len(session_keys)} session keys")
                )

                # Create audit logs in batches
                self._create_audit_logs_in_batches(
                    audit_logs_count,
                    batch_size,
                    users,
                    paths,
                    user_agents,
                    ip_addresses,
                    session_keys,
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f"Successfully created {audit_logs_count} audit log entries!"
                    )
                )

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating test data: {str(e)}"))
            raise

        # Show summary statistics
        self._show_summary()

    def _clean_test_data(self):
        """Clean existing test data"""
        # Note: Due to foreign key constraints, we need to delete in order
        AccessLog.objects.all().delete()
        LogSessionKey.objects.all().delete()
        LogIpAddress.objects.all().delete()
        LogUserAgent.objects.all().delete()
        LogPath.objects.all().delete()
        LogUser.objects.all().delete()

        # Also clean Django users with test-related usernames
        User.objects.filter(username__startswith="testuser").delete()
        User.objects.filter(username__startswith="admin").delete()

        self.stdout.write(self.style.SUCCESS("Cleaned existing test data"))

    def _create_users(self, regular_count: int, admin_count: int) -> list[LogUser]:
        """Create test users and corresponding LogUser entries"""
        users = []

        # Create regular users
        for i in range(regular_count):
            username = f"testuser{i+1}"
            email = f"testuser{i+1}@example.com"

            # Create Django user
            django_user = User.objects.create_user(
                username=username,
                email=email,
                password="testpass123",
                first_name="Test",
                last_name=f"User {i+1}",
            )

            # Create LogUser
            log_user = LogUser.objects.create(id=django_user.id, user_name=username)
            users.append(log_user)

        # Create admin users
        for i in range(admin_count):
            username = f"admin{i+1}"
            email = f"admin{i+1}@example.com"

            # Create Django admin user
            django_user = User.objects.create_superuser(
                username=username,
                email=email,
                password="adminpass123",
                first_name="Admin",
                last_name=f"User {i+1}",
            )

            # Create LogUser
            log_user = LogUser.objects.create(id=django_user.id, user_name=username)
            users.append(log_user)

        return users

    def _create_paths(self, count: int) -> list[LogPath]:
        """Create test URL paths"""
        common_paths = [
            "/",
            "/home/",
            "/about/",
            "/contact/",
            "/login/",
            "/logout/",
            "/admin/",
            "/api/users/",
            "/api/posts/",
            "/api/comments/",
            "/dashboard/",
            "/profile/",
            "/settings/",
            "/help/",
            "/search/",
            "/blog/",
            "/news/",
            "/products/",
            "/services/",
            "/pricing/",
        ]

        paths = []
        # Use common paths first, then generate more if needed
        for i in range(count):
            if i < len(common_paths):  # noqa: SIM108
                path = common_paths[i]
            else:
                # Generate additional paths
                path = f"/page{i+1}/"

            log_path = LogPath.objects.create(
                path=path,
                exclude_path=random.choice([True, False])
                if random.random() < 0.1
                else False,  # 10% chance of exclusion
            )
            paths.append(log_path)

        return paths

    def _create_user_agents(self) -> list[LogUserAgent]:
        """Create test user agents"""
        user_agent_strings = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        ]

        user_agents = []
        for user_agent_string in user_agent_strings:
            user_agent = LogUserAgent.from_user_agent_string(user_agent_string)
            # Randomly exclude some user agents
            if random.random() < 0.2:  # 20% chance of exclusion
                user_agent.exclude_agent = True
                user_agent.save()
            user_agents.append(user_agent)

        return user_agents

    def _create_ip_addresses(self) -> list[LogIpAddress]:
        """Create test IP addresses"""
        ip_addresses = []

        # Common IP ranges
        ip_patterns = [
            "192.168.1.{}",
            "10.0.0.{}",
            "172.16.0.{}",
            "203.0.113.{}",  # TEST-NET-3
            "198.51.100.{}",  # TEST-NET-2
        ]

        for pattern in ip_patterns:
            for i in range(1, 21):  # Create 20 IPs per pattern
                ip_address = LogIpAddress.objects.create(address=pattern.format(i))
                ip_addresses.append(ip_address)

        return ip_addresses

    def _create_session_keys(self) -> list[LogSessionKey]:
        """Create test session keys"""
        session_keys = []

        for _i in range(50):  # Create 50 different session keys
            session_key = LogSessionKey.objects.create(
                key=f"session_key_{uuid.uuid4().hex}"
            )
            session_keys.append(session_key)

        return session_keys

    def _create_audit_logs_in_batches(
        self,
        total_count: int,
        batch_size: int,
        users: list[LogUser],
        paths: list[LogPath],
        user_agents: list[LogUserAgent],
        ip_addresses: list[LogIpAddress],
        session_keys: list[LogSessionKey],
    ):
        """Create audit logs in batches for better performance"""

        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        status_codes = [200, 201, 204, 301, 302, 400, 401, 403, 404, 500]

        # Weight status codes (more successful responses)
        status_weights = [30, 10, 5, 3, 3, 2, 1, 1, 2, 1]

        created_count = 0
        batch_count = 0

        while created_count < total_count:
            batch_logs = []
            current_batch_size = min(batch_size, total_count - created_count)

            for _ in range(current_batch_size):
                # Generate timestamp within last 30 days
                end_time = timezone.now()
                start_time = end_time - timedelta(days=30)
                random_time = start_time + (end_time - start_time) * random.random()

                # Create access log data
                log_data = {
                    "path": random.choice(paths),
                    "referrer": random.choice(paths) if random.random() < 0.7 else None,
                    "response_url": random.choice(paths)
                    if random.random() < 0.3
                    else None,
                    "method": random.choice(methods),
                    "data": self._generate_request_data(),
                    "status_code": random.choices(status_codes, weights=status_weights)[
                        0
                    ],
                    "user_agent": random.choice(user_agents).user_agent,
                    "user_agent_normalized": random.choice(user_agents),
                    "user": random.choice(users)
                    if random.random() < 0.8
                    else None,  # 80% chance of having a user
                    "session_key": random.choice(session_keys)
                    if random.random() < 0.9
                    else None,  # 90% chance of session
                    "ip": random.choice(ip_addresses),
                    "timestamp": random_time,
                    "in_always_log_urls": random.random() < 0.1,  # 10% chance
                    "in_sample_urls": random.random() < 0.2,  # 20% chance
                    "sample_rate": random.choice([0.1, 0.5, 1.0]),
                }

                batch_logs.append(AccessLog(**log_data))

            # Bulk create the batch
            AccessLog.objects.bulk_create(batch_logs)
            created_count += current_batch_size
            batch_count += 1

            self.stdout.write(
                f"Created batch {batch_count}: {created_count}/{total_count} audit logs"
            )

    def _generate_request_data(self) -> dict:
        """Generate realistic request data"""
        data_types = [
            {},  # Empty data
            {"query": "search term"},
            {"page": random.randint(1, 10)},
            {"user_id": random.randint(1, 100)},
            {"action": random.choice(["create", "update", "delete", "view"])},
            {
                "form_data": {
                    "name": f"Test User {random.randint(1, 100)}",
                    "email": f"user{random.randint(1, 100)}@example.com",
                }
            },
            {"api_version": "v1", "endpoint": "users"},
            {"filters": {"status": "active", "category": "test"}},
        ]

        return random.choice(data_types)

    def _show_summary(self):
        """Show summary statistics of created data"""
        self.stdout.write(self.style.SUCCESS("\n=== Test Data Summary ==="))

        # Count records
        users_count = LogUser.objects.count()
        paths_count = LogPath.objects.count()
        user_agents_count = LogUserAgent.objects.count()
        ip_addresses_count = LogIpAddress.objects.count()
        session_keys_count = LogSessionKey.objects.count()
        audit_logs_count = AccessLog.objects.count()

        self.stdout.write(f"Users: {users_count}")
        self.stdout.write(f"URL Paths: {paths_count}")
        self.stdout.write(f"User Agents: {user_agents_count}")
        self.stdout.write(f"IP Addresses: {ip_addresses_count}")
        self.stdout.write(f"Session Keys: {session_keys_count}")
        self.stdout.write(f"Audit Logs: {audit_logs_count}")

        # Show some exclusion statistics
        excluded_paths = LogPath.objects.filter(exclude_path=True).count()
        excluded_agents = LogUserAgent.objects.filter(exclude_agent=True).count()

        self.stdout.write(f"\nExcluded Paths: {excluded_paths}")
        self.stdout.write(f"Excluded User Agents: {excluded_agents}")

        # Show Django users
        django_users_count = User.objects.count()
        admin_users_count = User.objects.filter(is_superuser=True).count()

        self.stdout.write(f"\nDjango Users: {django_users_count}")
        self.stdout.write(f"Admin Users: {admin_users_count}")

        self.stdout.write(
            self.style.SUCCESS("\nTest data creation completed successfully!")
        )
