from datetime import timedelta

from django.contrib import admin
from django.contrib.admin import SimpleListFilter
from django.db import models
from django.db.models.functions import Cast
from django.utils import timezone
from django.utils.html import mark_safe

from django_audit_log.user_agent_utils import UserAgentUtil

from .models import (
    AccessLog,
    LogIpAddress,
    LogPath,
    LogSessionKey,
    LogUser,
    LogUserAgent,
)

try:
    from rangefilter.filters import DateRangeFilter  # type: ignore

    HAS_RANGE_FILTER = True
except ImportError:
    HAS_RANGE_FILTER = False


# Base admin classes
class ReadOnlyAdmin(admin.ModelAdmin):
    """Base admin class for read-only models."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class BrowserTypeFilter(SimpleListFilter):
    """Filter logs by browser type."""

    title = "Browser"
    parameter_name = "browser_type"

    def lookups(self, request, model_admin):
        return (
            ("chrome", "Chrome"),
            ("firefox", "Firefox"),
            ("safari", "Safari"),
            ("edge", "Edge"),
            ("ie", "Internet Explorer"),
            ("opera", "Opera"),
            ("mobile", "Mobile Browsers"),
            ("bots", "Bots/Crawlers"),
            ("other", "Other Browsers"),
        )

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        value = self.value()

        if value == "chrome":
            return queryset.filter(user_agent_normalized__browser="Chrome").exclude(
                user_agent_normalized__browser="Chromium"
            )
        elif value == "firefox":
            return queryset.filter(user_agent_normalized__browser="Firefox")
        elif value == "safari":
            return queryset.filter(user_agent_normalized__browser="Safari").exclude(
                user_agent_normalized__browser="Chrome"
            )
        elif value == "edge":
            return queryset.filter(user_agent_normalized__browser="Edge")
        elif value == "ie":
            return queryset.filter(user_agent_normalized__browser="Internet Explorer")
        elif value == "opera":
            return queryset.filter(user_agent_normalized__browser="Opera")
        elif value == "mobile":
            return queryset.filter(user_agent_normalized__device_type="Mobile")
        elif value == "bots":
            return queryset.filter(user_agent_normalized__is_bot=True)
        elif value == "other":
            major_browsers = [
                "Chrome",
                "Firefox",
                "Safari",
                "Edge",
                "Internet Explorer",
                "Opera",
            ]
            return queryset.exclude(user_agent_normalized__browser__in=major_browsers)


class DeviceTypeFilter(SimpleListFilter):
    """Filter logs by device type."""

    title = "Device Type"
    parameter_name = "device_type"

    def lookups(self, request, model_admin):
        return (
            ("desktop", "Desktop"),
            ("mobile", "Mobile"),
            ("tablet", "Tablet"),
            ("bot", "Bot/Crawler"),
        )

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        value = self.value()
        if value == "mobile":
            return queryset.filter(user_agent_normalized__device_type="Mobile")
        elif value == "tablet":
            return queryset.filter(user_agent_normalized__device_type="Tablet")
        elif value == "bot":
            return queryset.filter(user_agent_normalized__is_bot=True)
        elif value == "desktop":
            return queryset.filter(
                user_agent_normalized__device_type="Desktop",
                user_agent_normalized__is_bot=False,
            )


class AccessLogAdmin(ReadOnlyAdmin):
    """Admin class for AccessLog model."""

    list_display = (
        "method",
        "path",
        "status_code",
        "user",
        "ip",
        "browser_type",
        "timestamp",
    )
    list_filter = (
        "method",
        "status_code",
        "user",
        BrowserTypeFilter,
        DeviceTypeFilter,
        "timestamp",
    )
    search_fields = ("path__path", "user__user_name")
    date_hierarchy = "timestamp"
    readonly_fields = (
        "path",
        "referrer",
        "response_url",
        "method",
        "data",
        "status_code",
        "user_agent",
        "user_agent_normalized",
        "normalized_user_agent",
        "user",
        "session_key",
        "ip",
        "timestamp",
    )

    def browser_type(self, obj):
        """Return a simplified browser type."""
        if obj.user_agent_normalized:
            return obj.user_agent_normalized.browser
        return "Unknown"

    browser_type.short_description = "Browser"

    def normalized_user_agent(self, obj):
        """Show the normalized user agent info."""
        if not obj.user_agent_normalized:
            return "No user agent data"

        ua_info = {
            "browser": obj.user_agent_normalized.browser,
            "browser_version": obj.user_agent_normalized.browser_version,
            "os": obj.user_agent_normalized.operating_system,
            "os_version": obj.user_agent_normalized.operating_system_version,
            "device_type": obj.user_agent_normalized.device_type,
            "is_bot": obj.user_agent_normalized.is_bot,
            "raw": obj.user_agent or obj.user_agent_normalized.user_agent,
        }

        html = f"""
        <style>
            .ua-info {{ margin: 10px 0; }}
            .ua-key {{ font-weight: bold; width: 120px; display: inline-block; }}
            .ua-browser {{ color: #0066cc; }}
            .ua-os {{ color: #28a745; }}
            .ua-device {{ color: #fd7e14; }}
            .ua-raw {{ margin-top: 15px; font-family: monospace; font-size: 12px;
                      padding: 10px; background-color: #f8f9fa; border-radius: 4px; word-break: break-all; }}
        </style>
        <div class="ua-info">
            <div><span class="ua-key">Browser:</span> <span class="ua-browser">{ua_info['browser']}</span></div>
            <div><span class="ua-key">Version:</span> {ua_info['browser_version'] or 'Unknown'}</div>
            <div><span class="ua-key">OS:</span> <span class="ua-os">{ua_info['os']}</span></div>
            <div><span class="ua-key">OS Version:</span> {ua_info['os_version'] or 'Unknown'}</div>
            <div><span class="ua-key">Device Type:</span> <span class="ua-device">{ua_info['device_type']}</span></div>
            <div><span class="ua-key">Is Bot/Crawler:</span> {ua_info['is_bot']}</div>
            <div class="ua-raw">{ua_info['raw']}</div>
        </div>
        """

        return mark_safe(html)

    normalized_user_agent.short_description = "Normalized User Agent"

    def changelist_view(self, request, extra_context=None):
        """Override to add user agent statistics to the changelist view."""
        # Only add stats if we're not filtering
        if len(request.GET) <= 1:  # Just the page number or nothing
            extra_context = extra_context or {}
            extra_context["user_agent_summary"] = self.get_user_agent_summary()
        return super().changelist_view(request, extra_context=extra_context)

    def get_user_agent_summary(self):
        """Generate a summary of user agent statistics."""
        from django.db.models import Count

        # Get normalized user agent data with counts
        normalized_user_agents = (
            LogUserAgent.objects.annotate(count=Count("access_logs"))
            .values("browser", "operating_system", "device_type", "is_bot", "count")
            .order_by("-count")[:1000]
        )  # Limit to 1000 most common for performance

        # Get legacy user agent data (for records with user_agent_normalized=NULL)
        legacy_user_agents = (
            AccessLog.objects.filter(
                user_agent_normalized__isnull=True, user_agent__isnull=False
            )
            .exclude(user_agent="")
            .values_list("user_agent")
            .annotate(count=Count("user_agent"))
            .order_by("-count")[:1000]
        )

        if not normalized_user_agents and not legacy_user_agents:
            return "No user agent data available"

        # Initialize categories
        categories = {
            "browsers": {},
            "operating_systems": {},
            "device_types": {},
            "bots": 0,
            "total": 0,
        }

        # Process normalized user agents (more efficient)
        for agent in normalized_user_agents:
            count = agent["count"]
            categories["total"] += count

            # Add to browser counts
            browser = agent["browser"] or "Unknown"
            if browser not in categories["browsers"]:
                categories["browsers"][browser] = 0
            categories["browsers"][browser] += count

            # Add to OS counts
            os = agent["operating_system"] or "Unknown"
            if os not in categories["operating_systems"]:
                categories["operating_systems"][os] = 0
            categories["operating_systems"][os] += count

            # Add to device type counts
            device = agent["device_type"] or "Unknown"
            if device not in categories["device_types"]:
                categories["device_types"][device] = 0
            categories["device_types"][device] += count

            # Count bots
            if agent["is_bot"]:
                categories["bots"] += count

        # Process legacy user agents
        if legacy_user_agents:
            legacy_categories = UserAgentUtil.categorize_user_agents(legacy_user_agents)

            # Merge legacy data
            categories["total"] += legacy_categories["total"]
            categories["bots"] += legacy_categories["bots"]

            for browser, count in legacy_categories["browsers"].items():
                if browser not in categories["browsers"]:
                    categories["browsers"][browser] = 0
                categories["browsers"][browser] += count

            for os, count in legacy_categories["operating_systems"].items():
                if os not in categories["operating_systems"]:
                    categories["operating_systems"][os] = 0
                categories["operating_systems"][os] += count

            for device, count in legacy_categories["device_types"].items():
                if device not in categories["device_types"]:
                    categories["device_types"][device] = 0
                categories["device_types"][device] += count

        # Create HTML for the statistics
        style = """
        <style>
            .ua-summary { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 4px; }
            .ua-summary h2 { margin-top: 0; color: #333; }
            .ua-chart { display: flex; flex-wrap: wrap; }
            .ua-column { flex: 1; min-width: 300px; margin-right: 20px; }
            .ua-bar { height: 20px; background-color: #4a6785; margin-bottom: 1px; }
            .ua-bar-container { margin-bottom: 5px; }
            .ua-bar-label { display: flex; justify-content: space-between; font-size: 12px; }
            .ua-bar-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .ua-bar-value { text-align: right; font-weight: bold; }
            .ua-category { margin-bottom: 20px; }
            .ua-category h3 { margin-top: 10px; color: #555; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        </style>
        """

        html = [
            style,
            '<div class="ua-summary"><h2>User Agent Statistics Summary</h2><div class="ua-chart">',
        ]

        # Browser statistics column
        html.append(
            '<div class="ua-column"><div class="ua-category"><h3>Top Browsers</h3>'
        )
        sorted_browsers = sorted(
            categories["browsers"].items(), key=lambda x: x[1], reverse=True
        )[:10]
        for browser, count in sorted_browsers:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar" style="width: {percentage}%;"></div>
                    <div class="ua-bar-label">
                        <div class="ua-bar-name">{browser}</div>
                        <div class="ua-bar-value">{percentage:.1f}%</div>
                    </div>
                </div>
            """
            )
        html.append("</div></div>")

        # OS statistics column
        html.append(
            '<div class="ua-column"><div class="ua-category"><h3>Top Operating Systems</h3>'
        )
        sorted_os = sorted(
            categories["operating_systems"].items(), key=lambda x: x[1], reverse=True
        )[:10]
        for os, count in sorted_os:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar" style="width: {percentage}%;"></div>
                    <div class="ua-bar-label">
                        <div class="ua-bar-name">{os}</div>
                        <div class="ua-bar-value">{percentage:.1f}%</div>
                    </div>
                </div>
            """
            )
        html.append("</div></div>")

        # Device type statistics column
        html.append(
            '<div class="ua-column"><div class="ua-category"><h3>Device Types</h3>'
        )
        sorted_devices = sorted(
            categories["device_types"].items(), key=lambda x: x[1], reverse=True
        )
        for device, count in sorted_devices:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar" style="width: {percentage}%;"></div>
                    <div class="ua-bar-label">
                        <div class="ua-bar-name">{device}</div>
                        <div class="ua-bar-value">{percentage:.1f}%</div>
                    </div>
                </div>
            """
            )
        html.append("</div></div>")

        html.append("</div>")  # Close chart

        # Summary stats
        bot_percentage = (
            (categories["bots"] / categories["total"]) * 100
            if categories["bots"] > 0
            else 0
        )
        top_browser = sorted_browsers[0][0] if sorted_browsers else "Unknown"
        top_browser_pct = (
            sorted_browsers[0][1] / categories["total"] * 100 if sorted_browsers else 0
        )
        top_os = sorted_os[0][0] if sorted_os else "Unknown"
        top_os_pct = sorted_os[0][1] / categories["total"] * 100 if sorted_os else 0

        html.append(
            f"""
            <div style="margin-top: 15px; font-size: 13px;">
                <p>Based on {categories['total']} requests •
                Bot/Crawler traffic: {bot_percentage:.1f}% •
                Top browser: {top_browser} ({top_browser_pct:.1f}%) •
                Top OS: {top_os} ({top_os_pct:.1f}%)</p>
            </div>
        """
        )

        html.append("</div>")  # Close summary

        return mark_safe("".join(html))


class LogPathAdmin(ReadOnlyAdmin):
    """Admin class for LogPath model."""

    list_display = ("path", "exclude_path")
    list_filter = ("exclude_path",)
    search_fields = ("path",)
    readonly_fields = ("path",)
    actions = ["delete_records_for_paths"]

    def get_readonly_fields(self, request, obj=None):
        """Make exclude_path editable for existing objects, but keep path readonly."""
        if obj:  # Editing an existing object
            return ("path",)  # Only path is readonly
        else:  # Adding a new object (shouldn't happen due to ReadOnlyAdmin)
            return ("path", "exclude_path")

    @admin.action(description="Delete access log records for selected paths")
    def delete_records_for_paths(self, request, queryset):
        """Delete all AccessLog records for the selected paths."""
        from django.contrib import messages

        total_deleted = 0
        for path in queryset:
            count, _ = AccessLog.objects.filter(path=path).delete()
            total_deleted += count

        if total_deleted > 0:
            messages.success(
                request,
                f"Successfully deleted {total_deleted} access log records for {queryset.count()} path(s).",
            )
        else:
            messages.warning(
                request,
                f"No access log records found for the selected {queryset.count()} path(s).",
            )


class LogSessionKeyAdmin(ReadOnlyAdmin):
    """Admin class for LogSessionKey model."""

    list_display = ("key",)
    search_fields = ("key",)
    readonly_fields = ("key",)


class ActivityLevelFilter(SimpleListFilter):
    """Filter users by their activity level in a time period."""

    title = "Activity Level"
    parameter_name = "activity"

    def lookups(self, request, model_admin):
        return (
            ("high", "High (10+ requests)"),
            ("medium", "Medium (3-9 requests)"),
            ("low", "Low (1-2 requests)"),
            ("inactive", "Inactive (no requests)"),
            ("recent", "Active in last 7 days"),
        )

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        if self.value() == "high":
            return queryset.annotate(count=models.Count("accesslog")).filter(
                count__gte=10
            )

        if self.value() == "medium":
            return queryset.annotate(count=models.Count("accesslog")).filter(
                count__gte=3, count__lte=9
            )

        if self.value() == "low":
            return queryset.annotate(count=models.Count("accesslog")).filter(
                count__gte=1, count__lte=2
            )

        if self.value() == "inactive":
            return queryset.annotate(count=models.Count("accesslog")).filter(count=0)

        if self.value() == "recent":
            seven_days_ago = timezone.now() - timedelta(days=7)
            return queryset.filter(accesslog__timestamp__gte=seven_days_ago).distinct()


class MultipleIPFilter(SimpleListFilter):
    """Filter users who have used multiple IP addresses."""

    title = "IP Usage"
    parameter_name = "ip_usage"

    def lookups(self, request, model_admin):
        return (
            ("multiple", "Multiple IPs"),
            ("single", "Single IP"),
        )

    def queryset(self, request, queryset):
        if not self.value():
            return queryset

        if self.value() == "multiple":
            return queryset.annotate(
                ip_count=models.Count("accesslog__ip", distinct=True)
            ).filter(ip_count__gt=1)

        if self.value() == "single":
            return queryset.annotate(
                ip_count=models.Count("accesslog__ip", distinct=True)
            ).filter(ip_count=1)


class LogUserAdmin(ReadOnlyAdmin):
    """Admin class for LogUser model."""

    list_display = (
        "id",
        "user_name",
        "ip_addresses_count",
        "access_count",
        "last_active",
    )
    search_fields = ("user_name",)
    readonly_fields = (
        "id",
        "user_name",
        "ip_addresses_used",
        "url_access_stats",
        "recent_activity",
        "user_agent_stats",
        "distinct_user_agents",
    )

    # Set up the list_filter with conditional DateRangeFilter if available
    if HAS_RANGE_FILTER:
        list_filter = (
            ActivityLevelFilter,
            MultipleIPFilter,
            ("accesslog__timestamp", DateRangeFilter),
        )
    else:
        list_filter = (ActivityLevelFilter, MultipleIPFilter)

    actions = ["clear_anonymous_logs", "delete_records_for_users"]

    @admin.action(description="Delete all logs for anonymous user")
    def clear_anonymous_logs(self, request, queryset):
        from django.contrib import messages

        from .models import AccessLog

        # Only allow this action for the anonymous user
        anonymous_users = queryset.filter(id=0)
        if not anonymous_users.exists():
            self.message_user(
                request, "No anonymous user selected.", level=messages.WARNING
            )
            return
        count, _ = AccessLog.objects.filter(user_id=0).delete()
        self.message_user(
            request,
            f"Deleted {count} access logs for anonymous user.",
            level=messages.SUCCESS,
        )

    @admin.action(description="Delete access log records for selected users")
    def delete_records_for_users(self, request, queryset):
        """Delete all AccessLog records for the selected users."""
        from django.contrib import messages

        total_deleted = 0
        for user in queryset:
            count, _ = AccessLog.objects.filter(user=user).delete()
            total_deleted += count

        if total_deleted > 0:
            messages.success(
                request,
                f"Successfully deleted {total_deleted} access log records for {queryset.count()} user(s).",
            )
        else:
            messages.warning(
                request,
                f"No access log records found for the selected {queryset.count()} user(s).",
            )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(
            access_count=models.Count("accesslog"),
            ip_count=models.Count("accesslog__ip", distinct=True),
            last_activity=models.Max("accesslog__timestamp"),
        )
        return qs

    def access_count(self, obj):
        return obj.access_count

    access_count.admin_order_field = "access_count"
    access_count.short_description = "Total Accesses"

    def ip_addresses_count(self, obj):
        return obj.ip_count

    ip_addresses_count.admin_order_field = "ip_count"
    ip_addresses_count.short_description = "Unique IPs"

    def last_active(self, obj):
        """Return the last activity time for this user."""
        if hasattr(obj, "last_activity") and obj.last_activity:
            return obj.last_activity
        return "Never"

    last_active.admin_order_field = "last_activity"
    last_active.short_description = "Last Active"

    def user_agent_stats(self, obj):
        """Show user agent statistics for this user with charts."""
        from django.db.models import Count

        # Get user agent data with counts using the normalized model
        user_agents = (
            AccessLog.objects.filter(user=obj)
            .exclude(user_agent_normalized__isnull=True)
            .values(
                "user_agent_normalized__browser",
                "user_agent_normalized__operating_system",
                "user_agent_normalized__device_type",
                "user_agent_normalized__is_bot",
            )
            .annotate(count=Count("id"))
            .order_by("-count")
        )

        if not user_agents:
            return "No user agent data available"

        # Initialize categories
        categories = {
            "browsers": {},
            "operating_systems": {},
            "device_types": {},
            "bots": 0,
            "total": 0,
        }

        # Process normalized user agents
        for agent in user_agents:
            count = agent["count"]
            categories["total"] += count

            # Add to browser counts
            browser = agent["user_agent_normalized__browser"] or "Unknown"
            if browser not in categories["browsers"]:
                categories["browsers"][browser] = 0
            categories["browsers"][browser] += count

            # Add to OS counts
            os = agent["user_agent_normalized__operating_system"] or "Unknown"
            if os not in categories["operating_systems"]:
                categories["operating_systems"][os] = 0
            categories["operating_systems"][os] += count

            # Add to device type counts
            device = agent["user_agent_normalized__device_type"] or "Unknown"
            if device not in categories["device_types"]:
                categories["device_types"][device] = 0
            categories["device_types"][device] += count

            # Count bots
            if agent["user_agent_normalized__is_bot"]:
                categories["bots"] += count

        # Create HTML for the statistics
        style = """
        <style>
            .ua-stats { width: 100%; margin-top: 20px; }
            .ua-stats h3 { margin-top: 20px; color: #333; }
            .ua-chart { display: flex; margin: 15px 0; }
            .ua-bar { height: 30px; min-width: 2px; background-color: #4a6785; margin-right: 1px; }
            .ua-bar-container { display: flex; align-items: center; margin-bottom: 8px; }
            .ua-bar-label { width: 120px; text-align: right; padding-right: 10px; }
            .ua-bar-value { margin-left: 10px; font-weight: bold; }
            .ua-category { margin-bottom: 30px; }
            .ua-bot-note { margin-top: 15px; font-style: italic; color: #666; }
        </style>
        """

        html = [style, '<div class="ua-stats">']

        # Browser statistics
        html.append('<div class="ua-category"><h3>Browsers</h3>')
        sorted_browsers = sorted(
            categories["browsers"].items(), key=lambda x: x[1], reverse=True
        )
        for browser, count in sorted_browsers:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{browser}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # OS statistics
        html.append('<div class="ua-category"><h3>Operating Systems</h3>')
        sorted_os = sorted(
            categories["operating_systems"].items(), key=lambda x: x[1], reverse=True
        )
        for os, count in sorted_os:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{os}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # Device type statistics
        html.append('<div class="ua-category"><h3>Device Types</h3>')
        sorted_devices = sorted(
            categories["device_types"].items(), key=lambda x: x[1], reverse=True
        )
        for device, count in sorted_devices:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{device}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # Bot percentage
        if categories["bots"] > 0:
            bot_percentage = (categories["bots"] / categories["total"]) * 100
            html.append(
                f'<div class="ua-bot-note">Bot/Crawler traffic: {categories["bots"]} requests ({bot_percentage:.1f}%)</div>'
            )

        html.append("</div>")

        return mark_safe("".join(html))

    user_agent_stats.short_description = "User Agent Statistics"

    def recent_activity(self, obj):
        """Show the most recent activity for this user."""
        recent_logs = AccessLog.objects.filter(user=obj).order_by("-timestamp")[:10]

        if not recent_logs:
            return "No recent activity"

        style = """
        <style>
            .activity-list { margin: 10px 0; }
            .activity-list .timestamp { color: #666; font-size: 0.9em; }
            .activity-list .method { font-weight: bold; display: inline-block; width: 50px; }
            .activity-list .method-GET { color: #28a745; }
            .activity-list .method-POST { color: #007bff; }
            .activity-list .method-PUT { color: #fd7e14; }
            .activity-list .method-DELETE { color: #dc3545; }
            .activity-list .status { font-weight: bold; }
            .activity-list .status-success { color: #28a745; }
            .activity-list .status-redirect { color: #fd7e14; }
            .activity-list .status-error { color: #dc3545; }
        </style>
        """

        html = [style, '<div class="activity-list">']
        for log in recent_logs:
            # Determine status class
            status_class = ""
            if log.status_code:
                if 200 <= log.status_code < 300:
                    status_class = "status-success"
                elif 300 <= log.status_code < 400:
                    status_class = "status-redirect"
                elif log.status_code >= 400:
                    status_class = "status-error"

            # Format the log entry
            status_html = (
                f'<span class="status {status_class}">[{log.status_code}]</span>'
                if log.status_code
                else ""
            )
            html.append(
                f"<div>"
                f'<span class="timestamp">{log.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</span> '
                f'<span class="method method-{log.method}">{log.method}</span> '
                f'<span class="path">{log.path}</span> '
                f"{status_html}"
                f"</div>"
            )
        html.append("</div>")

        return mark_safe("".join(html))

    recent_activity.short_description = "Recent Activity (Last 10 Actions)"

    def ip_addresses_used(self, obj):
        """Return HTML list of IP addresses used by this user with request counts."""
        from django.db.models import Count

        # More efficient query with annotation
        ip_stats = (
            AccessLog.objects.filter(user=obj)
            .values("ip__address")
            .annotate(count=Count("ip"))
            .order_by("-count")
        )

        if not ip_stats:
            return "No IP addresses recorded"

        style = """
        <style>
            .ip-list { margin: 10px 0; padding: 0; list-style-type: none; }
            .ip-list li { padding: 5px 10px; margin-bottom: 5px; background-color: #f8f9fa; border-radius: 4px; }
            .ip-count { font-weight: bold; color: #0066cc; }
        </style>
        """

        html = [style, '<ul class="ip-list">']
        for item in ip_stats:
            html.append(
                f'<li>{item["ip__address"]} - <span class="ip-count">{item["count"]} requests</span></li>'
            )
        html.append("</ul>")

        return mark_safe("".join(html))

    ip_addresses_used.short_description = "IP Addresses Used"

    def url_access_stats(self, obj):
        """Return HTML table of URLs accessed by this user with counts."""
        from django.db.models import Count

        # More efficient query with annotation
        url_stats = (
            AccessLog.objects.filter(user=obj)
            .values("path__path")
            .annotate(count=Count("path"))
            .order_by("-count")[:50]
        )  # Limit to top 50 to avoid performance issues

        if not url_stats:
            return "No URLs recorded"

        style = """
        <style>
            .url-table { border-collapse: collapse; width: 100%; margin-top: 10px; }
            .url-table th { background-color: #4a6785; color: white; text-align: left; padding: 8px; }
            .url-table td { border: 1px solid #ddd; padding: 8px; }
            .url-table tr:nth-child(even) { background-color: #f2f2f2; }
            .url-table tr:hover { background-color: #ddd; }
            .url-count { text-align: center; font-weight: bold; }
        </style>
        """

        html = [style, '<table class="url-table"><tr><th>URL</th><th>Count</th></tr>']
        for item in url_stats:
            html.append(
                f'<tr><td>{item["path__path"]}</td><td class="url-count">{item["count"]}</td></tr>'
            )

        if len(url_stats) == 50:
            html.append(
                '<tr><td colspan="2" style="text-align:center; font-style:italic;">Showing top 50 results</td></tr>'
            )

        html.append("</table>")

        return mark_safe("".join(html))

    url_access_stats.short_description = "URL Access Statistics"

    def distinct_user_agents(self, obj):
        """Display a list of all distinct user agents used by this user."""
        from django.db.models import Count

        # Get all distinct user agents for this user
        user_agents = (
            AccessLog.objects.filter(user=obj)
            .exclude(user_agent_normalized__isnull=True)
            .values(
                "user_agent_normalized__user_agent",
                "user_agent_normalized__browser",
                "user_agent_normalized__browser_version",
                "user_agent_normalized__operating_system",
                "user_agent_normalized__operating_system_version",
                "user_agent_normalized__device_type",
                "user_agent_normalized__is_bot",
            )
            .annotate(count=Count("user_agent_normalized"))
            .order_by("-count")
        )

        if not user_agents:
            return "No user agent data available"

        style = """
        <style>
            .ua-list {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            .ua-list th {
                background-color: #4a6785;
                color: white;
                text-align: left;
                padding: 8px;
            }
            .ua-list td {
                border: 1px solid #ddd;
                padding: 8px;
                vertical-align: top;
            }
            .ua-list tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            .ua-list tr:hover {
                background-color: #ddd;
            }
            .ua-count {
                font-weight: bold;
                color: #0066cc;
            }
            .ua-raw {
                font-family: monospace;
                font-size: 0.9em;
                color: #666;
                margin-top: 4px;
            }
            .ua-bot {
                color: #dc3545;
                font-weight: bold;
            }
        </style>
        """

        html = [
            style,
            """<table class="ua-list">
                <tr>
                    <th>Browser</th>
                    <th>Operating System</th>
                    <th>Device Type</th>
                    <th>Usage Count</th>
                    <th>Raw User Agent</th>
                </tr>""",
        ]

        for agent in user_agents:
            browser = f"{agent['user_agent_normalized__browser']} {agent['user_agent_normalized__browser_version'] or ''}"
            os_version = (
                f" {agent['user_agent_normalized__operating_system_version']}"
                if agent["user_agent_normalized__operating_system_version"]
                else ""
            )
            os = f"{agent['user_agent_normalized__operating_system']}{os_version}"

            bot_class = (
                ' class="ua-bot"' if agent["user_agent_normalized__is_bot"] else ""
            )

            html.append(f"""
                <tr{bot_class}>
                    <td>{browser}</td>
                    <td>{os}</td>
                    <td>{agent['user_agent_normalized__device_type']}</td>
                    <td class="ua-count">{agent['count']}</td>
                    <td>
                        <div class="ua-raw">{agent['user_agent_normalized__user_agent']}</div>
                    </td>
                </tr>
            """)

        html.append("</table>")

        return mark_safe("".join(html))

    distinct_user_agents.short_description = "Distinct User Agents"


class LogIpAddressAdmin(ReadOnlyAdmin):
    """Admin class for LogIpAddress model."""

    list_display = ("address", "user_count", "request_count")
    search_fields = ("address",)
    readonly_fields = ("address", "user_agent_stats")

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(
            request_count=models.Count("accesslog"),
            user_count=models.Count("accesslog__user", distinct=True),
        )
        return qs

    def user_count(self, obj):
        return obj.user_count

    user_count.admin_order_field = "user_count"
    user_count.short_description = "Unique Users"

    def request_count(self, obj):
        return obj.request_count

    request_count.admin_order_field = "request_count"
    request_count.short_description = "Total Requests"

    def user_agent_stats(self, obj):
        """Show user agent statistics for this IP address."""
        from django.db.models import Count

        # Get user agent data with counts
        user_agents = (
            AccessLog.objects.filter(ip=obj, user_agent__isnull=False)
            .exclude(user_agent="")
            .values_list("user_agent")
            .annotate(count=Count("user_agent"))
            .order_by("-count")
        )

        if not user_agents:
            return "No user agent data available"

        # Get categorized data
        categories = UserAgentUtil.categorize_user_agents(user_agents)

        # Create HTML for the statistics
        style = """
        <style>
            .ua-stats { width: 100%; margin-top: 20px; }
            .ua-stats h3 { margin-top: 20px; color: #333; }
            .ua-chart { display: flex; margin: 15px 0; }
            .ua-bar { height: 30px; min-width: 2px; background-color: #4a6785; margin-right: 1px; }
            .ua-bar-container { display: flex; align-items: center; margin-bottom: 8px; }
            .ua-bar-label { width: 120px; text-align: right; padding-right: 10px; }
            .ua-bar-value { margin-left: 10px; font-weight: bold; }
            .ua-category { margin-bottom: 30px; }
            .ua-bot-note { margin-top: 15px; font-style: italic; color: #666; }
        </style>
        """

        html = [style, '<div class="ua-stats">']

        # Browser statistics
        html.append('<div class="ua-category"><h3>Browsers</h3>')
        sorted_browsers = sorted(
            categories["browsers"].items(), key=lambda x: x[1], reverse=True
        )
        for browser, count in sorted_browsers:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{browser}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # OS statistics
        html.append('<div class="ua-category"><h3>Operating Systems</h3>')
        sorted_os = sorted(
            categories["operating_systems"].items(), key=lambda x: x[1], reverse=True
        )
        for os, count in sorted_os:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{os}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # Device type statistics
        html.append('<div class="ua-category"><h3>Device Types</h3>')
        sorted_devices = sorted(
            categories["device_types"].items(), key=lambda x: x[1], reverse=True
        )
        for device, count in sorted_devices:
            percentage = (count / categories["total"]) * 100
            html.append(
                f"""
                <div class="ua-bar-container">
                    <div class="ua-bar-label">{device}</div>
                    <div class="ua-bar" style="width: {max(percentage, 2)}%;"></div>
                    <div class="ua-bar-value">{count} ({percentage:.1f}%)</div>
                </div>
            """
            )
        html.append("</div>")

        # Bot percentage
        if categories["bots"] > 0:
            bot_percentage = (categories["bots"] / categories["total"]) * 100
            html.append(
                f'<div class="ua-bot-note">Bot/Crawler traffic: {categories["bots"]} requests ({bot_percentage:.1f}%)</div>'
            )

        html.append("</div>")

        return mark_safe("".join(html))

    user_agent_stats.short_description = "User Agent Statistics"


class LogUserAgentAdmin(ReadOnlyAdmin):
    """Admin class for LogUserAgent model."""

    list_display = (
        "browser",
        "browser_version",
        "operating_system",
        "operating_system_version",
        "device_type",
        "is_bot",
        "exclude_agent",
        "usage_count",
        "unique_users_count",
    )
    list_filter = (
        "browser",
        "operating_system",
        "device_type",
        "is_bot",
        "exclude_agent",
        "operating_system_version",
    )
    search_fields = ("user_agent", "browser", "operating_system")
    readonly_fields = (
        "user_agent",
        "browser",
        "browser_version",
        "operating_system",
        "operating_system_version",
        "device_type",
        "is_bot",
        "usage_details",
        "related_users",
    )
    actions = ["delete_records_for_agents"]

    @admin.action(description="Delete access log records for selected user agents")
    def delete_records_for_agents(self, request, queryset):
        """Delete all AccessLog records for the selected user agents."""
        from django.contrib import messages

        total_deleted = 0
        for user_agent in queryset:
            count, _ = AccessLog.objects.filter(
                user_agent_normalized=user_agent
            ).delete()
            total_deleted += count

        if total_deleted > 0:
            messages.success(
                request,
                f"Successfully deleted {total_deleted} access log records for {queryset.count()} user agent(s).",
            )
        else:
            messages.warning(
                request,
                f"No access log records found for the selected {queryset.count()} user agent(s).",
            )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(
            usage_count=models.Count("access_logs"),
            unique_users=models.Count("access_logs__user", distinct=True),
            # Add semantic version ordering
            version_as_int=models.Case(
                models.When(
                    operating_system_version__regex=r"^\d+$",
                    then=Cast("operating_system_version", models.IntegerField()),
                ),
                default=0,
                output_field=models.IntegerField(),
            ),
        ).order_by("operating_system", "-version_as_int", "operating_system_version")
        return qs

    def operating_system_version(self, obj):
        """Display the operating system version with semantic ordering."""
        return obj.operating_system_version

    operating_system_version.admin_order_field = "version_as_int"
    operating_system_version.short_description = "OS Version"

    def usage_count(self, obj):
        """Return number of times this user agent appears in logs."""
        return obj.usage_count

    usage_count.admin_order_field = "usage_count"
    usage_count.short_description = "Usage Count"

    def unique_users_count(self, obj):
        """Return number of unique users that have used this user agent."""
        return obj.unique_users

    unique_users_count.admin_order_field = "unique_users"
    unique_users_count.short_description = "Unique Users"

    def usage_details(self, obj):
        """Show details of how this user agent is used."""
        from django.db.models import Count

        # Get user count and IP count
        user_count = (
            AccessLog.objects.filter(user_agent_normalized=obj)
            .values("user")
            .distinct()
            .count()
        )

        ip_count = (
            AccessLog.objects.filter(user_agent_normalized=obj)
            .values("ip")
            .distinct()
            .count()
        )

        # Get top 10 paths accessed with this user agent
        top_paths = (
            AccessLog.objects.filter(user_agent_normalized=obj)
            .values("path__path")
            .annotate(count=Count("path"))
            .order_by("-count")[:10]
        )

        # Create HTML for the statistics
        style = """
        <style>
            .ua-usage { margin: 20px 0; }
            .ua-usage h3 { margin-top: 20px; color: #333; }
            .ua-usage-stat { margin-bottom: 10px; }
            .ua-stat-label { font-weight: bold; color: #555; }
            .ua-path-list { margin-top: 10px; }
            .ua-path-item { padding: 5px 0; border-bottom: 1px solid #eee; }
            .ua-path-count { font-weight: bold; color: #0066cc; margin-right: 10px; }
        </style>
        """

        html = [style, '<div class="ua-usage">']

        # Usage statistics
        html.append('<div class="ua-usage-stat">')
        html.append(
            f'<span class="ua-stat-label">Total requests:</span> {obj.usage_count}</div>'
        )
        html.append(
            f'<div class="ua-usage-stat"><span class="ua-stat-label">Unique users:</span> {user_count}</div>'
        )
        html.append(
            f'<div class="ua-usage-stat"><span class="ua-stat-label">Unique IP addresses:</span> {ip_count}</div>'
        )

        # Path statistics
        if top_paths:
            html.append("<h3>Top Accessed Paths</h3>")
            html.append('<div class="ua-path-list">')
            for item in top_paths:
                html.append(
                    f"""
                    <div class="ua-path-item">
                        <span class="ua-path-count">{item["count"]}</span>
                        <span class="ua-path-url">{item["path__path"]}</span>
                    </div>
                """
                )
            html.append("</div>")

        html.append("</div>")

        return mark_safe("".join(html))

    usage_details.short_description = "Usage Details"

    def related_users(self, obj):
        """Display a list of users who have used this user agent."""
        from django.db.models import Count
        from django.urls import reverse
        from django.utils.html import format_html

        # Get users who have used this user agent with their usage counts
        users = (
            AccessLog.objects.filter(user_agent_normalized=obj)
            .values("user__id", "user__user_name")
            .annotate(usage_count=Count("id"), last_used=models.Max("timestamp"))
            .order_by("-usage_count")
        )

        if not users:
            return "No users have used this user agent"

        style = """
        <style>
            .user-list {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            .user-list th {
                background-color: #4a6785;
                color: white;
                text-align: left;
                padding: 8px;
            }
            .user-list td {
                border: 1px solid #ddd;
                padding: 8px;
            }
            .user-list tr:nth-child(even) {
                background-color: #f2f2f2;
            }
            .user-list tr:hover {
                background-color: #ddd;
            }
            .user-count {
                text-align: center;
                font-weight: bold;
                color: #0066cc;
            }
            .user-link {
                color: #0066cc;
                text-decoration: none;
            }
            .user-link:hover {
                text-decoration: underline;
            }
            .last-used {
                color: #666;
                font-size: 0.9em;
            }
        </style>
        """

        html = [
            style,
            """<table class="user-list">
                <tr>
                    <th>User</th>
                    <th>Usage Count</th>
                    <th>Last Used</th>
                </tr>""",
        ]

        for user in users:
            # Create a link to the user's admin page
            user_url = reverse(
                "admin:django_audit_log_loguser_change", args=[user["user__id"]]
            )
            user_link = format_html(
                '<a class="user-link" href="{}">{}</a>',
                user_url,
                user["user__user_name"],
            )

            html.append(f"""
                <tr>
                    <td>{user_link}</td>
                    <td class="user-count">{user['usage_count']}</td>
                    <td class="last-used">{user['last_used'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
            """)

        html.append("</table>")

        return mark_safe("".join(html))

    related_users.short_description = "Users of this User Agent"


# Register models with their admin classes
admin.site.register(AccessLog, AccessLogAdmin)
admin.site.register(LogIpAddress, LogIpAddressAdmin)
admin.site.register(LogPath, LogPathAdmin)
admin.site.register(LogSessionKey, LogSessionKeyAdmin)
admin.site.register(LogUser, LogUserAdmin)
admin.site.register(LogUserAgent, LogUserAgentAdmin)
