"""
Log information about requests
This is mostly taken from the request
and intended to be used with the "AccessLogMixin"
"""

import random
import re
from typing import Any, NamedTuple, Optional
from urllib.parse import urlparse

# Django imports
from django.conf import settings
from django.db import models
from django.http.request import HttpRequest
from django.http.response import HttpResponse

# Third-party imports (if any)
try:
    from sentry_sdk import capture_exception  # type: ignore
except ImportError:
    # Fallback if sentry_sdk is not installed
    def capture_exception(exception):
        if settings.DEBUG:
            raise exception


class LogPath(models.Model):
    """
    Mostly for deduplication of URLS, keeps the Path, Referrer, or response URL (ie redirection from a POST)
    """

    path = models.CharField(max_length=4096, null=False, blank=True, editable=False)
    exclude_path = models.BooleanField(
        default=False,
        help_text="Exclude this URL path from logging",
        verbose_name="Exclude This URL",
    )

    class Meta:
        verbose_name = "Log Path"
        verbose_name_plural = "Log Paths"
        indexes = [
            models.Index(fields=["path"]),
            models.Index(fields=["exclude_path"]),  # Add index for performance
        ]

    @staticmethod
    def normalize_path(url: str) -> str:
        """
        Normalize a URL by removing method, server, and port information.
        Also handles relative URLs.

        Args:
            url: The URL to normalize

        Returns:
            str: The normalized path
        """
        if not url:
            return ""

        # Parse the URL
        parsed = urlparse(url)

        # If it's already just a path (no scheme/netloc), return it cleaned
        if not parsed.scheme and not parsed.netloc:
            return parsed.path

        # Return just the path component
        return parsed.path

    @classmethod
    def from_request(cls, request: HttpRequest) -> "LogPath":
        """
        Create or get a LogPath instance from a request path.

        Args:
            request: The HTTP request object

        Returns:
            LogPath: The LogPath instance for the request path
        """
        normalized_path = cls.normalize_path(request.path)
        return cls.objects.get_or_create(path=normalized_path)[0]

    @classmethod
    def from_referrer(cls, request: HttpRequest) -> Optional["LogPath"]:
        """
        Create or get a LogPath instance from a request referrer.

        Args:
            request: The HTTP request object

        Returns:
            Optional[LogPath]: The LogPath instance for the referrer or None if no referrer
        """
        referrer = request.META.get("HTTP_REFERER")
        if not referrer:
            return None

        try:
            normalized_path = cls.normalize_path(referrer)
            return cls.objects.get_or_create(path=normalized_path)[0]
        except cls.MultipleObjectsReturned:
            # Log this situation as it indicates data inconsistency
            if settings.DEBUG:
                print(f"Multiple LogPath objects found for referrer: {referrer}")
            return cls.objects.filter(path=cls.normalize_path(referrer)).first()

    @classmethod
    def from_response(cls, response: HttpResponse | None) -> Optional["LogPath"]:
        """
        Create or get a LogPath instance from a response URL.

        Args:
            response: The HTTP response object

        Returns:
            Optional[LogPath]: The LogPath instance for the response URL or None if no URL
        """
        if response is None:
            return None

        try:
            normalized_path = cls.normalize_path(response.url)
            return cls.objects.get_or_create(path=normalized_path)[0]
        except AttributeError:
            return None

    def __str__(self) -> str:
        """Return a string representation of the LogPath."""
        return self.path


class LogSessionKey(models.Model):
    """
    Keep the user's session key
    Possibly useful to track user interaction over time
    """

    key = models.CharField(max_length=1024, null=False, blank=True, editable=False)

    class Meta:
        verbose_name = "Log Session Key"
        verbose_name_plural = "Log Session Keys"
        indexes = [
            models.Index(fields=["key"]),
        ]

    @classmethod
    def from_request(cls, request: HttpRequest) -> Optional["LogSessionKey"]:
        """
        Create or get a LogSessionKey instance from a request session key.

        Args:
            request: The HTTP request object

        Returns:
            Optional[LogSessionKey]: The LogSessionKey instance or None if no session key
        """
        key = request.session.session_key
        if key:
            return cls.objects.get_or_create(key=key)[0]
        return None

    def __str__(self) -> str:
        """Return a truncated string representation of the session key."""
        return f"{self.key[:5]}"


class LogUser(models.Model):
    """
    Rather than make a foreign-key to User, which may be deleted or changed,
    keep a record of the user ID and name
    """

    id = models.IntegerField(
        primary_key=True, editable=False
    )  # Should correspond to a User ID
    # This is the username of the first logged request. It should not change but sometimes
    # people do fix spelling mistakes etc.
    user_name = models.CharField(
        max_length=1024, null=False, blank=True, editable=False
    )

    class Meta:
        verbose_name = "Log User"
        verbose_name_plural = "Log Users"

    @classmethod
    def from_request(cls, request: HttpRequest) -> "LogUser":
        """
        Create or get a LogUser instance from a request user.

        Args:
            request: The HTTP request object

        Returns:
            LogUser: The LogUser instance
        """
        if request.user.is_anonymous:
            return cls.objects.get_or_create(id=0, user_name="anonymous")[0]
        return cls.objects.get_or_create(
            id=request.user.pk, defaults={"user_name": request.user.get_username()}
        )[0]

    def __str__(self) -> str:
        """Return a string representation of the logged user."""
        return f"{self.user_name} ({self.id})"


class LogIpAddress(models.Model):
    """
    Single field lists IP addresses of users
    """

    address = models.GenericIPAddressField(editable=False)

    class Meta:
        verbose_name = "Log IP Address"
        verbose_name_plural = "Log IP Addresses"
        indexes = [
            models.Index(fields=["address"]),
        ]

    @classmethod
    def from_request(cls, request: HttpRequest) -> "LogIpAddress":
        """
        Create or get a LogIpAddress instance from a request IP address.

        Args:
            request: The HTTP request object

        Returns:
            LogIpAddress: The LogIpAddress instance
        """
        # Get the IP address, accounting for proxies
        if request.META.get("HTTP_X_FORWARDED_FOR"):
            ip = request.META.get("HTTP_X_FORWARDED_FOR").split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")

        return cls.objects.get_or_create(address=ip)[0]

    def __str__(self) -> str:
        """Return a string representation of the IP address."""
        return self.address


class AccessLog(models.Model):
    """
    Primary model for logging access. You probably want to
    use a mixin - see "from_request method" - rather than directly accessing
    this.
    """

    # The source path, referrer, and response URL (if any)
    path = models.ForeignKey(
        LogPath, null=True, blank=True, on_delete=models.PROTECT, editable=False
    )
    referrer = models.ForeignKey(
        LogPath,
        null=True,
        blank=True,
        related_name="refers",
        on_delete=models.PROTECT,
        editable=False,
    )
    response_url = models.ForeignKey(
        LogPath,
        null=True,
        blank=True,
        related_name="response",
        on_delete=models.PROTECT,
        editable=False,
    )

    # Request type and content
    method = models.CharField(max_length=8, null=False, blank=True, editable=False)
    data = models.JSONField(help_text="Payload", editable=False)
    status_code = models.IntegerField(
        null=True, blank=True, help_text="Response code (200=OK)", editable=False
    )

    # User agent information (deprecated field kept for backward compatibility)
    user_agent = models.TextField(
        null=True,
        blank=True,
        help_text="User Agent string (deprecated)",
        editable=False,
    )

    # Foreign key to normalized user agent
    user_agent_normalized = models.ForeignKey(
        "LogUserAgent",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        editable=False,
        related_name="access_logs",
        help_text="Normalized user agent information",
    )

    # user details: username, ip address, session
    user = models.ForeignKey(
        LogUser, null=True, blank=True, on_delete=models.PROTECT, editable=False
    )
    session_key = models.ForeignKey(
        LogSessionKey, null=True, blank=True, on_delete=models.PROTECT, editable=False
    )
    ip = models.ForeignKey(
        LogIpAddress, null=True, blank=True, on_delete=models.PROTECT, editable=False
    )

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True, editable=False)

    # Sampling metadata fields
    in_always_log_urls = models.BooleanField(
        default=False,
        editable=False,
        help_text="Whether this URL matched a pattern in AUDIT_LOG_ALWAYS_LOG_URLS",
    )
    in_sample_urls = models.BooleanField(
        default=False,
        editable=False,
        help_text="Whether this URL matched a pattern in AUDIT_LOG_SAMPLE_URLS",
    )
    sample_rate = models.FloatField(
        null=True,
        blank=True,
        editable=False,
        help_text="The AUDIT_LOG_SAMPLE_RATE value when this log was created",
    )

    # Define a NamedTuple for sampling results
    class SamplingResult(NamedTuple):
        """Results from checking if a request should be sampled."""

        should_log: bool
        in_always_log_urls: bool
        in_sample_urls: bool
        sample_rate: float

    class Meta:
        verbose_name = "Access Log"
        verbose_name_plural = "Access Logs"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["method"]),
            models.Index(fields=["status_code"]),
        ]

    @classmethod
    def from_request(
        cls, request: HttpRequest, response: HttpResponse | None = None
    ) -> Optional["AccessLog"]:
        """
        Create an access log entry from a request and optional response.

        Args:
            request: The HTTP request object
            response: Optional HTTP response object

        Returns:
            Optional[AccessLog]: The created AccessLog instance or None if creation failed
        """
        # Get excluded IPs from settings
        excluded_ips = getattr(settings, "AUDIT_LOG_EXCLUDED_IPS", ["127.0.0.1"])

        # Check if the request IP is excluded
        ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[
            0
        ].strip() or request.META.get("REMOTE_ADDR")
        if ip in excluded_ips:
            return None

        # Get and process the user agent string early for bot exclusion
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        user_agent_obj = None
        if user_agent_string:
            user_agent_obj = LogUserAgent.from_user_agent_string(user_agent_string)

        # Check database-based user agent exclusion first, then fall back to settings
        if user_agent_obj and user_agent_obj.exclude_agent:
            return None

        # Backward compatibility: exclude bots if configured in settings and not already excluded by database
        exclude_bots = getattr(settings, "AUDIT_LOG_EXCLUDE_BOTS", False)
        if exclude_bots and user_agent_obj and user_agent_obj.is_bot:
            return None

        # Check database-based path exclusion early
        path_obj = LogPath.from_request(request)
        if path_obj and path_obj.exclude_path:
            return None

        # Enhanced URL exclusion: only exclude if status code is 200 (if response is present)
        excluded_url_patterns = getattr(settings, "AUDIT_LOG_EXCLUDED_URLS", [])
        path = request.path
        for pattern in excluded_url_patterns:
            if re.match(pattern, path):
                if response is not None and hasattr(response, "status_code"):
                    if response.status_code == 200:
                        return None
                elif response is None:
                    # If no response, keep old behavior (exclude unconditionally)
                    return None

        # Check if we should log this request based on sampling settings
        sampling_info = cls._check_sampling(request)
        if not sampling_info.should_log:
            return None

        def get_data() -> dict[str, Any]:
            """
            Extract cleaned GET and POST data,
            excluding "sensitive" fields

            Returns:
                Dict[str, Any]: Dictionary containing GET and POST data
            """
            # Create deepcopies to avoid modifying the original data
            post = request.POST.copy()

            # Remove sensitive fields
            sensitive_fields = ["password", "csrfmiddlewaretoken", "created_by"]
            for field in sensitive_fields:
                post.pop(field, None)

            get = dict(request.GET.copy())

            # Keep things short: drop if there is no GET or POST data
            data = {}
            if get:
                data["get"] = get
            if post:
                data["post"] = post
            return data

        try:
            return cls.objects.create(
                # The source path, referrer, and response URL (if any)
                path=LogPath.from_request(request),
                referrer=LogPath.from_referrer(request),
                response_url=LogPath.from_response(response) if response else None,
                # Request type and content
                method=request.method,
                data=get_data(),
                status_code=response.status_code if response else None,
                # User agent (storing both for backward compatibility)
                user_agent=user_agent_string,
                user_agent_normalized=user_agent_obj,
                # user details: username, ip address, session
                user=LogUser.from_request(request),
                session_key=LogSessionKey.from_request(request),
                ip=LogIpAddress.from_request(request),
                # Sampling metadata
                in_always_log_urls=sampling_info.in_always_log_urls,
                in_sample_urls=sampling_info.in_sample_urls,
                sample_rate=sampling_info.sample_rate,
            )
        except Exception as e:
            if settings.DEBUG:
                raise
            capture_exception(e)
            return None

    @classmethod
    def _check_sampling(cls, request: HttpRequest) -> "AccessLog.SamplingResult":
        """
        Check if a request should be logged based on sampling settings.

        Args:
            request: The HTTP request object

        Returns:
            SamplingResult: Named tuple containing sampling information
        """
        # Check database-based path exclusion first
        path = request.path
        path_obj = LogPath.objects.filter(path=path).first()
        if path_obj and path_obj.exclude_path:
            return cls.SamplingResult(
                should_log=False,
                in_always_log_urls=False,
                in_sample_urls=False,
                sample_rate=getattr(settings, "AUDIT_LOG_SAMPLE_RATE", 1.0),
            )

        # Exclude by URL pattern before any sampling logic
        excluded_url_patterns = getattr(settings, "AUDIT_LOG_EXCLUDED_URLS", [])
        for pattern in excluded_url_patterns:
            if re.match(pattern, path):
                return cls.SamplingResult(
                    should_log=False,
                    in_always_log_urls=False,
                    in_sample_urls=False,
                    sample_rate=getattr(settings, "AUDIT_LOG_SAMPLE_RATE", 1.0),
                )

        # Get settings with defaults
        sample_rate = getattr(settings, "AUDIT_LOG_SAMPLE_RATE", 1.0)
        always_log_urls = getattr(settings, "AUDIT_LOG_ALWAYS_LOG_URLS", [])
        sample_urls = getattr(settings, "AUDIT_LOG_SAMPLE_URLS", [])

        # If no URL patterns are specified in either list, fall back to sampling all URLs
        if not always_log_urls and not sample_urls:
            return cls.SamplingResult(
                should_log=random.random() < sample_rate,
                in_always_log_urls=False,
                in_sample_urls=False,
                sample_rate=sample_rate,
            )

        # First check if the URL should always be logged
        for pattern in always_log_urls:
            if re.match(pattern, path):
                return cls.SamplingResult(
                    should_log=True,
                    in_always_log_urls=True,
                    in_sample_urls=False,
                    sample_rate=sample_rate,
                )

        # Then check if the URL should be sampled
        for pattern in sample_urls:
            if re.match(pattern, path):
                return cls.SamplingResult(
                    should_log=random.random() < sample_rate,
                    in_always_log_urls=False,
                    in_sample_urls=True,
                    sample_rate=sample_rate,
                )

        # URLs not in either list are never logged
        return cls.SamplingResult(
            should_log=False,
            in_always_log_urls=False,
            in_sample_urls=False,
            sample_rate=sample_rate,
        )

    @classmethod
    def _should_log_request(cls, request: HttpRequest) -> bool:
        """
        Determine if the request should be logged based on sampling settings.

        Args:
            request: The HTTP request object

        Returns:
            bool: True if the request should be logged, False otherwise
        """
        return cls._check_sampling(request).should_log

    def __str__(self) -> str:
        """Return a string representation of the AccessLog."""
        status = f" [{self.status_code}]" if self.status_code else ""
        return f"{self.method} {self.path}{status} by {self.user} at {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class LogUserAgent(models.Model):
    """
    Store user agent strings to avoid duplication in AccessLog.
    Also provides pre-parsed categorization of user agents.
    """

    user_agent = models.TextField(unique=True, editable=False)
    browser = models.CharField(max_length=256, null=True, blank=True, editable=False)
    browser_version = models.CharField(
        max_length=256, null=True, blank=True, editable=False
    )
    operating_system = models.CharField(
        max_length=256, null=True, blank=True, editable=False
    )
    operating_system_version = models.CharField(
        max_length=256,
        null=True,
        blank=True,
        editable=False,
        help_text="Version of the operating system if available",
    )
    device_type = models.CharField(
        max_length=256, null=True, blank=True, editable=False
    )
    is_bot = models.BooleanField(default=False, editable=False)
    exclude_agent = models.BooleanField(
        default=False,
        help_text="Exclude this user agent from logging",
        verbose_name="Exclude Agent",
    )

    class Meta:
        verbose_name = "Log User Agent"
        verbose_name_plural = "Log User Agents"
        indexes = [
            models.Index(fields=["browser"]),
            models.Index(fields=["operating_system"]),
            models.Index(fields=["device_type"]),
            models.Index(fields=["is_bot"]),
            models.Index(fields=["exclude_agent"]),  # Add index for performance
        ]

    @classmethod
    def reimport_all(cls, batch_size=1000):
        """
        Reprocess all user agents with current parsing logic.
        This is useful when the parsing logic has been updated.

        Args:
            batch_size: Number of records to process in each batch

        Returns:
            dict: Summary of reimport results
        """
        from django.db import transaction

        from django_audit_log.user_agent_utils import UserAgentUtil

        # Get all distinct user agents
        total_agents = cls.objects.count()
        processed = 0
        updated = 0

        print(f"Found {total_agents} user agents to reprocess")

        # Process in batches to avoid memory issues
        for i in range(0, total_agents, batch_size):
            batch = cls.objects.all()[i : i + batch_size]

            with transaction.atomic():
                for agent in batch:
                    processed += 1

                    # Parse with current logic
                    info = UserAgentUtil.normalize_user_agent(agent.user_agent)

                    # Check if any fields would be updated
                    needs_update = (
                        agent.browser != info["browser"]
                        or agent.browser_version != info["browser_version"]
                        or agent.operating_system != info["os"]
                        or agent.operating_system_version != info["os_version"]
                        or agent.device_type != info["device_type"]
                        or agent.is_bot != info["is_bot"]
                    )

                    if needs_update:
                        agent.browser = info["browser"]
                        agent.browser_version = info["browser_version"]
                        agent.operating_system = info["os"]
                        agent.operating_system_version = info["os_version"]
                        agent.device_type = info["device_type"]
                        agent.is_bot = info["is_bot"]
                        agent.save()
                        updated += 1

            if processed % batch_size == 0 or processed == total_agents:
                print(
                    f"Processed {processed}/{total_agents} user agents, updated {updated}"
                )

        return {
            "total_agents": total_agents,
            "processed": processed,
            "updated": updated,
        }

    @classmethod
    def from_user_agent_string(cls, user_agent_string):
        """
        Create or get a LogUserAgent instance from a user agent string.
        Parses and categorizes the user agent during creation.

        Args:
            user_agent_string: The raw user agent string

        Returns:
            LogUserAgent: The LogUserAgent instance
        """
        if not user_agent_string:
            return None

        # Try to get existing user agent
        try:
            return cls.objects.get(user_agent=user_agent_string)
        except cls.DoesNotExist:
            # Parse user agent
            try:
                from django_audit_log.user_agent_utils import UserAgentUtil

                info = UserAgentUtil.normalize_user_agent(user_agent_string)

                return cls.objects.create(
                    user_agent=user_agent_string,
                    browser=info["browser"],
                    browser_version=info["browser_version"],
                    operating_system=info["os"],
                    operating_system_version=info["os_version"],
                    device_type=info["device_type"],
                    is_bot=info["is_bot"],
                )
            except ImportError:
                # If UserAgentUtil is not available, just store the string
                return cls.objects.create(
                    user_agent=user_agent_string,
                    browser="Unknown",
                    operating_system="Unknown",
                    device_type="Unknown",
                )

    def __str__(self):
        os_version = (
            f" {self.operating_system_version}" if self.operating_system_version else ""
        )
        return f"{self.browser} {self.browser_version or ''} on {self.operating_system}{os_version} ({self.device_type})"
