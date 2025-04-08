"""
Log information about requests
This is mostly taken from the request
and intended to be used with the "AccessLogMixin"
"""

from collections import defaultdict
from collections.abc import Iterable
from functools import reduce
from operator import or_
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urlparse
import random
import re

# Django imports
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models import Case, F, Q, QuerySet, When
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.urls import Resolver404, resolve
from django.urls.resolvers import ResolverMatch

# Third-party imports (if any)
try:
    from sentry_sdk import capture_exception
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

    class Meta:
        verbose_name = "Log Path"
        verbose_name_plural = "Log Paths"
        indexes = [
            models.Index(fields=["path"]),
        ]

    @property
    def parsed_path(self):
        """Parse the path using urlparse and return the result."""
        return urlparse(self.path)

    @property
    def resolver_match(self) -> Optional[ResolverMatch]:
        """
        Return the view name as it would be in the current schema.
        This may be different from the `view_name` attribute as
        code changes.
        
        Returns:
            Optional[ResolverMatch]: The resolver match object or None if path can't be resolved
        """
        try:
            return resolve(self.parsed_path.path)
        except Resolver404:
            return None

    @classmethod
    def from_request(cls, request: HttpRequest) -> "LogPath":
        """
        Create or get a LogPath instance from a request path.
        
        Args:
            request: The HTTP request object
            
        Returns:
            LogPath: The LogPath instance for the request path
        """
        return cls.objects.get_or_create(path=request.path)[0]

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
            return cls.objects.get_or_create(path=referrer)[0]
        except cls.MultipleObjectsReturned:
            # Log this situation as it indicates data inconsistency
            if settings.DEBUG:
                print(f"Multiple LogPath objects found for referrer: {referrer}")
            return cls.objects.filter(path=referrer).first()

    @classmethod
    def from_response(cls, response: Optional[HttpResponse]) -> Optional["LogPath"]:
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
            return cls.objects.get_or_create(path=response.url)[0]
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

    id = models.IntegerField(primary_key=True, editable=False)  # Should correspond to a User ID
    # This is the username of the first logged request. It should not change but sometimes
    # people do fix spelling mistakes etc.
    user_name = models.CharField(max_length=1024, null=False, blank=True, editable=False)
    
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
            id=request.user.pk, 
            defaults={"user_name": request.user.get_username()}
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
    path = models.ForeignKey(LogPath, null=True, blank=True, on_delete=models.PROTECT, editable=False)
    referrer = models.ForeignKey(LogPath, null=True, blank=True, related_name="refers", on_delete=models.PROTECT, editable=False)
    response_url = models.ForeignKey(LogPath, null=True, blank=True, related_name="response", on_delete=models.PROTECT, editable=False)

    # Request type and content
    method = models.CharField(max_length=8, null=False, blank=True, editable=False)
    data = models.JSONField(help_text="Payload", editable=False)
    status_code = models.IntegerField(null=True, blank=True, help_text="Response code (200=OK)", editable=False)
    
    # User agent information (deprecated field kept for backward compatibility)
    user_agent = models.TextField(null=True, blank=True, help_text="User Agent string (deprecated)", editable=False)
    
    # Foreign key to normalized user agent
    user_agent_normalized = models.ForeignKey("LogUserAgent", null=True, blank=True, on_delete=models.SET_NULL, editable=False, 
                                             related_name="access_logs", help_text="Normalized user agent information")

    # user details: username, ip address, session
    user = models.ForeignKey(LogUser, null=True, blank=True, on_delete=models.PROTECT, editable=False)
    session_key = models.ForeignKey(LogSessionKey, null=True, blank=True, on_delete=models.PROTECT, editable=False)
    ip = models.ForeignKey(LogIpAddress, null=True, blank=True, on_delete=models.PROTECT, editable=False)

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True, editable=False)
    
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
    def from_request(cls, request: HttpRequest, response: Optional[HttpResponse] = None) -> Optional["AccessLog"]:
        """
        Create an access log entry from a request and optional response.
        
        Args:
            request: The HTTP request object
            response: Optional HTTP response object
            
        Returns:
            Optional[AccessLog]: The created AccessLog instance or None if creation failed
        """
        # Check if we should log this request based on sampling settings
        if not cls._should_log_request(request):
            return None
            
        def get_data() -> Dict[str, Any]:
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
            
        # Get and process the user agent string
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent_obj = None
        if user_agent_string:
            user_agent_obj = LogUserAgent.from_user_agent_string(user_agent_string)

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
            )
        except Exception as e:
            if settings.DEBUG:
                raise
            capture_exception(e)
            return None
            
    @classmethod
    def _should_log_request(cls, request: HttpRequest) -> bool:
        """
        Determine if the request should be logged based on sampling settings.
        
        The decision is made based on:
        1. AUDIT_LOG_ALWAYS_LOG_URLS - URLs that should always be logged (no sampling)
        2. AUDIT_LOG_SAMPLE_URLS - URLs that should be sampled at the sample rate
        3. All other URLs are never logged
        
        Args:
            request: The HTTP request object
            
        Returns:
            bool: True if the request should be logged, False otherwise
        """
        # Default sample rate is 100% for URLs in the sampling list
        sample_rate = getattr(settings, 'AUDIT_LOG_SAMPLE_RATE', 1.0)
        
        # Get URL lists from settings with empty lists as defaults
        always_log_urls = getattr(settings, 'AUDIT_LOG_ALWAYS_LOG_URLS', [])
        sample_urls = getattr(settings, 'AUDIT_LOG_SAMPLE_URLS', [])
        
        # If no URL patterns are specified in either list, fall back to logging all URLs at the sample rate
        # This maintains backward compatibility
        if not always_log_urls and not sample_urls:
            return random.random() < sample_rate
        
        path = request.path
        
        # First check if the URL should always be logged
        for pattern in always_log_urls:
            if re.match(pattern, path):
                return True
                
        # Then check if the URL should be sampled
        for pattern in sample_urls:
            if re.match(pattern, path):
                return random.random() < sample_rate
                
        # URLs not in either list are never logged
        return False

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
    browser = models.CharField(max_length=50, null=True, blank=True, editable=False)
    browser_version = models.CharField(max_length=20, null=True, blank=True, editable=False)
    operating_system = models.CharField(max_length=50, null=True, blank=True, editable=False)
    device_type = models.CharField(max_length=20, null=True, blank=True, editable=False)
    is_bot = models.BooleanField(default=False, editable=False)
    
    class Meta:
        verbose_name = "Log User Agent"
        verbose_name_plural = "Log User Agents"
        indexes = [
            models.Index(fields=["browser"]),
            models.Index(fields=["operating_system"]),
            models.Index(fields=["device_type"]),
            models.Index(fields=["is_bot"]),
        ]
    
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
                from django_audit_log.admin import UserAgentUtil
                info = UserAgentUtil.normalize_user_agent(user_agent_string)
                
                return cls.objects.create(
                    user_agent=user_agent_string,
                    browser=info['browser'],
                    browser_version=info['browser_version'],
                    operating_system=info['os'],
                    device_type=info['device_type'],
                    is_bot=info['is_bot']
                )
            except ImportError:
                # If UserAgentUtil is not available, just store the string
                return cls.objects.create(
                    user_agent=user_agent_string,
                    browser="Unknown",
                    operating_system="Unknown",
                    device_type="Unknown"
                )
    
    def __str__(self):
        return f"{self.browser} {self.browser_version or ''} on {self.operating_system} ({self.device_type})"
