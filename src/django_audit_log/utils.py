from django.db import transaction
from django.db.models import Count

from .models import AccessLog, LogUserAgent


def migrate_user_agents(batch_size=1000):
    """
    Migrate existing user agent strings to the normalized LogUserAgent model.
    This can be run as a separate management command or as part of a data migration.

    Args:
        batch_size: Number of records to process in each batch

    Returns:
        dict: Summary of migration results
    """
    # Import UserAgentUtil here to avoid circular import
    from .user_agent_utils import UserAgentUtil

    # Get all distinct user agents that haven't been normalized yet
    distinct_user_agents = (
        AccessLog.objects.filter(
            user_agent_normalized__isnull=True, user_agent__isnull=False
        )
        .exclude(user_agent="")
        .values_list("user_agent")
        .annotate(count=Count("user_agent"))
        .order_by("-count")
    )

    total_agents = distinct_user_agents.count()
    processed_agents = 0
    created_agents = 0
    updated_logs = 0

    print(f"Found {total_agents} distinct user agent strings to process")

    # Process user agents in batches
    for i in range(0, total_agents, batch_size):
        batch = distinct_user_agents[i : i + batch_size]

        # Create normalized user agents for this batch
        for ua_string, _count in batch:
            # Skip empty strings
            if not ua_string:
                continue

            processed_agents += 1

            # Try to get existing user agent
            try:
                user_agent = LogUserAgent.objects.get(user_agent=ua_string)
            except LogUserAgent.DoesNotExist:
                # Parse and create new user agent
                info = UserAgentUtil.normalize_user_agent(ua_string)
                user_agent = LogUserAgent.objects.create(
                    user_agent=ua_string,
                    browser=info["browser"],
                    browser_version=info["browser_version"],
                    operating_system=info["os"],
                    device_type=info["device_type"],
                    is_bot=info["is_bot"],
                )
                created_agents += 1

            # Update all logs with this user agent string
            with transaction.atomic():
                batch_logs_updated = AccessLog.objects.filter(
                    user_agent=ua_string, user_agent_normalized__isnull=True
                ).update(user_agent_normalized=user_agent)

                updated_logs += batch_logs_updated

        print(
            f"Processed {processed_agents}/{total_agents} user agents, updated {updated_logs} logs"
        )

    return {
        "total_agents": total_agents,
        "processed_agents": processed_agents,
        "created_agents": created_agents,
        "updated_logs": updated_logs,
    }


def get_user_agent_statistics():
    """
    Generate statistics about user agent usage.

    Returns:
        dict: Statistics about user agents in the database
    """
    # Count normalized and non-normalized user agents
    total_logs = AccessLog.objects.count()
    normalized_logs = AccessLog.objects.filter(
        user_agent_normalized__isnull=False
    ).count()
    non_normalized_logs = AccessLog.objects.filter(
        user_agent_normalized__isnull=True
    ).count()

    # Count unique user agents
    unique_user_agents = LogUserAgent.objects.count()

    # Get top browsers
    top_browsers = (
        LogUserAgent.objects.values("browser")
        .annotate(count=Count("access_logs"))
        .order_by("-count")[:10]
    )

    # Get top operating systems
    top_os = (
        LogUserAgent.objects.values("operating_system")
        .annotate(count=Count("access_logs"))
        .order_by("-count")[:10]
    )

    # Get device type distribution
    device_types = (
        LogUserAgent.objects.values("device_type")
        .annotate(count=Count("access_logs"))
        .order_by("-count")
    )

    # Get bot percentage
    bot_count = (
        LogUserAgent.objects.filter(is_bot=True).aggregate(count=Count("access_logs"))[
            "count"
        ]
        or 0
    )

    return {
        "total_logs": total_logs,
        "normalized_logs": normalized_logs,
        "non_normalized_logs": non_normalized_logs,
        "normalized_percentage": (
            (normalized_logs / total_logs * 100) if total_logs else 0
        ),
        "unique_user_agents": unique_user_agents,
        "top_browsers": top_browsers,
        "top_os": top_os,
        "device_types": device_types,
        "bot_count": bot_count,
        "bot_percentage": (bot_count / normalized_logs * 100) if normalized_logs else 0,
    }
