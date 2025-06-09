import types

import factory
import pytest
from django.contrib import admin
from django.contrib.admin.sites import site
from django.http import HttpRequest
from django.urls import reverse

from django_audit_log import admin as audit_admin

from .models import (
    AccessLog,
    LogIpAddress,
    LogPath,
    LogSessionKey,
    LogUser,
    LogUserAgent,
)
from .user_agent_utils import UserAgentUtil


def test_stub_math():
    assert 1 + 1 == 2


@pytest.mark.django_db
def test_admin_pages_accessible(admin_client):
    # Get all registered models
    for model, _model_admin in site._registry.items():
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        url = reverse(f"admin:{app_label}_{model_name}_changelist")
        response = admin_client.get(url)
        assert (
            response.status_code == 200
        ), f"Admin page for {model.__name__} not accessible"


class LogUserFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = LogUser

    id = factory.Sequence(lambda n: n + 1)
    user_name = factory.Faker("user_name")


@pytest.mark.django_db
def test_loguser_factory():
    user = LogUserFactory()
    assert LogUser.objects.filter(pk=user.pk).exists()


class LogPathFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = "django_audit_log.LogPath"

    path = factory.Faker("uri_path")
    exclude_path = False  # Add back now that field exists


class LogSessionKeyFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = "django_audit_log.LogSessionKey"

    key = factory.Faker("uuid4")


class LogIpAddressFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = "django_audit_log.LogIpAddress"

    address = factory.Faker("ipv4")


class LogUserAgentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = "django_audit_log.LogUserAgent"

    user_agent = factory.Faker("user_agent")
    browser = factory.Faker("chrome")
    browser_version = factory.Faker("numerify", text="##.0")
    operating_system = factory.Faker("linux_platform_token")
    operating_system_version = factory.Faker("numerify", text="##.##")
    device_type = factory.Iterator(["Desktop", "Mobile", "Tablet"])
    is_bot = False
    exclude_agent = False  # Add back now that field exists


@pytest.mark.django_db
def test_logpath_factory():
    obj = LogPathFactory()
    assert LogPath.objects.filter(pk=obj.pk).exists()


@pytest.mark.django_db
def test_logsessionkey_factory():
    obj = LogSessionKeyFactory()
    assert LogSessionKey.objects.filter(pk=obj.pk).exists()


@pytest.mark.django_db
def test_logipaddress_factory():
    obj = LogIpAddressFactory()
    assert LogIpAddress.objects.filter(pk=obj.pk).exists()


@pytest.mark.django_db
def test_loguseragent_factory():
    obj = LogUserAgentFactory()
    assert LogUserAgent.objects.filter(pk=obj.pk).exists()


class AccessLogFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = AccessLog

    path = factory.SubFactory(LogPathFactory)
    referrer = factory.SubFactory(LogPathFactory)
    response_url = factory.SubFactory(LogPathFactory)
    method = factory.Iterator(["GET", "POST", "PUT", "DELETE"])
    data = factory.LazyFunction(lambda: {"foo": "bar"})
    status_code = 200
    user_agent = factory.Faker("user_agent")
    user_agent_normalized = factory.SubFactory(LogUserAgentFactory)
    user = factory.SubFactory(LogUserFactory)
    session_key = factory.SubFactory(LogSessionKeyFactory)
    ip = factory.SubFactory(LogIpAddressFactory)
    in_always_log_urls = False
    in_sample_urls = False
    sample_rate = 1.0


@pytest.mark.django_db
def test_accesslog_factory():
    log = AccessLogFactory()
    assert AccessLog.objects.filter(pk=log.pk).exists()
    assert log.user is not None
    assert log.ip is not None
    assert log.session_key is not None
    assert log.path is not None
    assert log.user_agent_normalized is not None


@pytest.mark.django_db
def test_logpath_normalize_path():
    assert LogPath.normalize_path("https://example.com/foo/bar") == "/foo/bar"
    assert LogPath.normalize_path("/foo/bar") == "/foo/bar"
    assert LogPath.normalize_path("") == ""


@pytest.mark.django_db
def test_logpath_from_request():
    request = HttpRequest()
    request.path = "/test/path"
    obj = LogPath.from_request(request)
    assert obj.path == "/test/path"
    assert LogPath.objects.filter(path="/test/path").exists()


@pytest.mark.django_db
def test_logpath_from_referrer():
    request = HttpRequest()
    request.META["HTTP_REFERER"] = "https://example.com/ref/path"
    obj = LogPath.from_referrer(request)
    assert obj.path == "/ref/path"
    assert LogPath.objects.filter(path="/ref/path").exists()

    # No referrer
    request2 = HttpRequest()
    assert LogPath.from_referrer(request2) is None


@pytest.mark.django_db
def test_logpath_from_response():
    class DummyResponse:
        url = "https://example.com/resp/path"

    response = DummyResponse()
    obj = LogPath.from_response(response)
    assert obj.path == "/resp/path"
    assert LogPath.objects.filter(path="/resp/path").exists()
    # None response
    assert LogPath.from_response(None) is None

    # Response with no url
    class NoUrl:
        pass

    assert LogPath.from_response(NoUrl()) is None


@pytest.mark.django_db
def test_logsessionkey_from_request():
    request = HttpRequest()
    request.session = types.SimpleNamespace(session_key="abc123")
    obj = LogSessionKey.from_request(request)
    assert obj.key == "abc123"
    assert LogSessionKey.objects.filter(key="abc123").exists()
    # No session key
    request2 = HttpRequest()
    request2.session = types.SimpleNamespace(session_key=None)
    assert LogSessionKey.from_request(request2) is None


@pytest.mark.django_db
def test_loguser_from_request(db, django_user_model):
    # Anonymous user
    request = HttpRequest()
    request.user = types.SimpleNamespace(is_anonymous=True)
    obj = LogUser.from_request(request)
    assert obj.id == 0
    assert obj.user_name == "anonymous"
    # Authenticated user
    user = django_user_model.objects.create(username="bob", id=42)
    request2 = HttpRequest()
    request2.user = user
    obj2 = LogUser.from_request(request2)
    assert obj2.id == user.pk
    assert obj2.user_name == user.username


@pytest.mark.django_db
def test_logipaddress_from_request():
    request = HttpRequest()
    request.META["REMOTE_ADDR"] = "1.2.3.4"
    obj = LogIpAddress.from_request(request)
    assert obj.address == "1.2.3.4"
    assert LogIpAddress.objects.filter(address="1.2.3.4").exists()
    # With X-Forwarded-For
    request2 = HttpRequest()
    request2.META["HTTP_X_FORWARDED_FOR"] = "5.6.7.8, 9.10.11.12"
    obj2 = LogIpAddress.from_request(request2)
    assert obj2.address == "5.6.7.8"
    assert LogIpAddress.objects.filter(address="5.6.7.8").exists()


@pytest.mark.django_db
def test_loguseragent_from_user_agent_string():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212"
    obj = LogUserAgent.from_user_agent_string(ua)
    assert obj.user_agent == ua
    assert obj.browser == "Chrome"
    assert obj.operating_system == "Windows 10"
    assert LogUserAgent.objects.filter(user_agent=ua).exists()
    # None input
    assert LogUserAgent.from_user_agent_string(None) is None


def test_useragentutil_normalize_user_agent():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.212"
    info = UserAgentUtil.normalize_user_agent(ua)
    assert info["browser"] == "Chrome"
    assert info["os"] == "Windows 10"
    assert (
        info["device_type"] == "Mobile"
        or info["device_type"] == "Desktop"
        or info["device_type"] == "Unknown"
    )
    # Eskola APK
    eskola_ua = "tl.eskola.eskola_app-1.2.3-release/Pixel4"
    info2 = UserAgentUtil.normalize_user_agent(eskola_ua)
    assert info2["browser"] == "Eskola APK"
    assert info2["os"] == "Android"
    assert "Device:" in info2["os_version"]
    # Bot
    bot_ua = "Googlebot/2.1 (+http://www.google.com/bot.html)"
    info3 = UserAgentUtil.normalize_user_agent(bot_ua)
    assert info3["is_bot"] is True


@pytest.mark.django_db
def test_readonlyadmin_permissions():
    class DummyRequest:
        pass

    dummy = DummyRequest()
    ro_admin = audit_admin.ReadOnlyAdmin(LogUser, admin.site)
    assert ro_admin.has_add_permission(dummy) is False
    assert ro_admin.has_change_permission(dummy) is False
    assert ro_admin.has_delete_permission(dummy) is False


@pytest.mark.django_db
def test_accesslogadmin_browser_type():
    log = AccessLogFactory()
    admin_obj = audit_admin.AccessLogAdmin(AccessLog, admin.site)
    assert admin_obj.browser_type(log) == log.user_agent_normalized.browser
    log.user_agent_normalized = None
    assert admin_obj.browser_type(log) == "Unknown"


@pytest.mark.django_db
def test_accesslogadmin_normalized_user_agent():
    log = AccessLogFactory()
    admin_obj = audit_admin.AccessLogAdmin(AccessLog, admin.site)
    html = admin_obj.normalized_user_agent(log)
    assert "ua-info" in html
    log.user_agent_normalized = None
    assert "No user agent data" in admin_obj.normalized_user_agent(log)


@pytest.mark.django_db
def test_loguseradmin_access_count():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user)
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    obj = user
    obj.access_count = 1
    assert admin_obj.access_count(obj) == 1


@pytest.mark.django_db
def test_loguseradmin_ip_addresses_count():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user)
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    obj = user
    obj.ip_count = 2
    assert admin_obj.ip_addresses_count(obj) == 2


@pytest.mark.django_db
def test_loguseradmin_last_active():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user)
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    obj = user
    from django.utils import timezone

    now = timezone.now()
    obj.last_activity = now
    assert (
        str(admin_obj.last_active(obj))[:4].isdigit()
        or admin_obj.last_active(obj) == "Never"
    )
    # No last_activity
    obj2 = LogUserFactory()
    assert admin_obj.last_active(obj2) == "Never"


@pytest.mark.django_db
def test_loguseradmin_user_agent_stats():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user)
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    html = admin_obj.user_agent_stats(user)
    assert "ua-stats" in html or "No user agent data available" in html


@pytest.mark.django_db
def test_loguseradmin_recent_activity():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user)
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    html = admin_obj.recent_activity(user)
    assert "activity-list" in html or "No recent activity" in html


@pytest.mark.django_db
def test_loguseradmin_ip_addresses_used():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user, ip=LogIpAddressFactory())
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    html = admin_obj.ip_addresses_used(user)
    assert "ip-list" in html or "No IP addresses recorded" in html


@pytest.mark.django_db
def test_loguseradmin_url_access_stats():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user, path=LogPathFactory())
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    html = admin_obj.url_access_stats(user)
    assert "url-table" in html or "No URLs recorded" in html


@pytest.mark.django_db
def test_loguseradmin_distinct_user_agents():
    user = LogUserFactory()
    _log = AccessLogFactory(user=user, user_agent_normalized=LogUserAgentFactory())
    admin_obj = audit_admin.LogUserAdmin(LogUser, admin.site)
    html = admin_obj.distinct_user_agents(user)
    assert "ua-raw" in html or "No user agent data available" in html


@pytest.mark.django_db
def test_logipaddressadmin_user_count():
    ip = LogIpAddressFactory()
    _log = AccessLogFactory(ip=ip)
    admin_obj = audit_admin.LogIpAddressAdmin(LogIpAddress, admin.site)
    obj = ip
    obj.user_count = 1
    assert admin_obj.user_count(obj) == 1


@pytest.mark.django_db
def test_logipaddressadmin_request_count():
    ip = LogIpAddressFactory()
    _log = AccessLogFactory(ip=ip)
    admin_obj = audit_admin.LogIpAddressAdmin(LogIpAddress, admin.site)
    obj = ip
    obj.request_count = 2
    assert admin_obj.request_count(obj) == 2


@pytest.mark.django_db
def test_logipaddressadmin_user_agent_stats():
    ip = LogIpAddressFactory()
    _log = AccessLogFactory(ip=ip)
    admin_obj = audit_admin.LogIpAddressAdmin(LogIpAddress, admin.site)
    html = admin_obj.user_agent_stats(ip)
    assert "ua-stats" in html or "No user agent data available" in html


@pytest.mark.django_db
def test_loguseragentadmin_usage_count():
    ua = LogUserAgentFactory()
    admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, admin.site)
    obj = ua
    obj.usage_count = 3
    assert admin_obj.usage_count(obj) == 3


@pytest.mark.django_db
def test_loguseragentadmin_unique_users_count():
    ua = LogUserAgentFactory()
    admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, admin.site)
    obj = ua
    obj.unique_users = 2
    assert admin_obj.unique_users_count(obj) == 2


@pytest.mark.django_db
def test_loguseragentadmin_usage_details():
    ua = LogUserAgentFactory()
    _log = AccessLogFactory(user_agent_normalized=ua)
    admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, admin.site)
    ua.usage_count = 1
    html = admin_obj.usage_details(ua)
    assert "ua-usage" in html


@pytest.mark.django_db
def test_loguseragentadmin_related_users():
    """Test related_users method of LogUserAgentAdmin."""
    # Create a user agent and access log
    user_agent = LogUserAgentFactory()
    user = LogUserFactory()
    AccessLogFactory(user_agent_normalized=user_agent, user=user)

    admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
    result = admin_obj.related_users(user_agent)
    assert "table" in result
    assert str(user.user_name) in result


# New tests for database exclusion features
@pytest.mark.django_db
class TestDatabaseExclusion:
    """Test database-based exclusion functionality."""

    def test_loguseragent_exclude_agent_field_exists(self):
        """Test that LogUserAgent model has exclude_agent field."""
        user_agent = LogUserAgentFactory()
        # This will fail until we add the field, which is expected
        assert hasattr(user_agent, "exclude_agent")
        assert user_agent.exclude_agent is False  # Default value

    def test_logpath_exclude_path_field_exists(self):
        """Test that LogPath model has exclude_path field."""
        path = LogPathFactory()
        # This will fail until we add the field, which is expected
        assert hasattr(path, "exclude_path")
        assert path.exclude_path is False  # Default value

    def test_user_agent_exclusion_prevents_logging(self):
        """Test that setting exclude_agent=True prevents AccessLog creation."""
        # Create a user agent with exclusion enabled
        user_agent = LogUserAgentFactory(exclude_agent=True)

        # Create a mock request
        request = HttpRequest()
        request.path = "/test/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": user_agent.user_agent,
            "REMOTE_ADDR": "127.0.0.1",
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the user agent lookup to return our excluded agent
        original_method = LogUserAgent.from_user_agent_string
        LogUserAgent.from_user_agent_string = classmethod(lambda cls, ua: user_agent)

        try:
            # Attempt to create access log
            result = AccessLog.from_request(request)
            # Should return None due to exclusion
            assert result is None
        finally:
            # Restore original method
            LogUserAgent.from_user_agent_string = original_method

    def test_user_agent_non_exclusion_allows_logging(self, settings):
        """Test that exclude_agent=False allows normal logging."""
        # Configure settings to ensure sampling allows logging
        settings.AUDIT_LOG_SAMPLE_RATE = 1.0  # Always log when sampled
        settings.AUDIT_LOG_ALWAYS_LOG_URLS = [r"^/test/.*"]  # Always log test paths
        settings.AUDIT_LOG_EXCLUDED_IPS = []  # Don't exclude any IPs for this test

        # Create a user agent without exclusion
        user_agent = LogUserAgentFactory(exclude_agent=False)

        # Create a mock request
        request = HttpRequest()
        request.path = "/test/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": user_agent.user_agent,
            "REMOTE_ADDR": "192.168.1.100",  # Use non-excluded IP
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the user agent lookup
        original_method = LogUserAgent.from_user_agent_string
        LogUserAgent.from_user_agent_string = classmethod(lambda cls, ua: user_agent)

        try:
            # Attempt to create access log
            result = AccessLog.from_request(request)
            # Should create log entry
            assert result is not None
            assert result.user_agent_normalized == user_agent
        finally:
            # Restore original method
            LogUserAgent.from_user_agent_string = original_method

    def test_path_exclusion_prevents_logging(self):
        """Test that setting exclude_path=True prevents AccessLog creation."""
        # Create a path with exclusion enabled
        path = LogPathFactory(path="/excluded/path", exclude_path=True)

        # Create a mock request
        request = HttpRequest()
        request.path = "/excluded/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Test Browser)",
            "REMOTE_ADDR": "127.0.0.1",
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the path lookup to return our excluded path
        original_method = LogPath.from_request
        LogPath.from_request = classmethod(lambda cls, req: path)

        try:
            # Attempt to create access log
            result = AccessLog.from_request(request)
            # Should return None due to path exclusion
            assert result is None
        finally:
            # Restore original method
            LogPath.from_request = original_method

    def test_path_non_exclusion_allows_logging(self, settings):
        """Test that exclude_path=False allows normal logging."""
        # Configure settings to ensure sampling allows logging
        settings.AUDIT_LOG_SAMPLE_RATE = 1.0  # Always log when sampled
        settings.AUDIT_LOG_ALWAYS_LOG_URLS = [
            r"^/allowed/.*"
        ]  # Always log allowed paths
        settings.AUDIT_LOG_EXCLUDED_IPS = []  # Don't exclude any IPs for this test

        # Create a path without exclusion
        path = LogPathFactory(path="/allowed/path", exclude_path=False)

        # Create a mock request
        request = HttpRequest()
        request.path = "/allowed/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": "Mozilla/5.0 (Test Browser)",
            "REMOTE_ADDR": "192.168.1.100",  # Use non-excluded IP
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the path lookup
        original_method = LogPath.from_request
        LogPath.from_request = classmethod(lambda cls, req: path)

        try:
            # Attempt to create access log
            result = AccessLog.from_request(request)
            # Should create log entry
            assert result is not None
            assert result.path == path
        finally:
            # Restore original method
            LogPath.from_request = original_method

    def test_sampling_method_respects_path_exclusion(self):
        """Test that _check_sampling method respects database path exclusion."""
        # Create an excluded path
        LogPathFactory(path="/api/excluded", exclude_path=True)

        # Create a mock request
        request = HttpRequest()
        request.path = "/api/excluded"

        # Test the sampling method
        result = AccessLog._check_sampling(request)

        # Should return should_log=False due to database exclusion
        assert result.should_log is False
        assert result.in_always_log_urls is False
        assert result.in_sample_urls is False


@pytest.mark.django_db
class TestAdminInterfaceChanges:
    """Test admin interface modifications for exclusion fields."""

    def test_loguseragent_admin_list_display_includes_exclude_agent(self):
        """Test that LogUserAgentAdmin includes exclude_agent in list_display."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        assert "exclude_agent" in admin_obj.list_display

    def test_loguseragent_admin_list_filter_includes_exclude_agent(self):
        """Test that LogUserAgentAdmin includes exclude_agent in list_filter."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        assert "exclude_agent" in admin_obj.list_filter

    def test_loguseragent_admin_exclude_agent_not_readonly(self):
        """Test that exclude_agent is not in readonly_fields (should be editable)."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        assert "exclude_agent" not in admin_obj.readonly_fields

    def test_logpath_admin_list_display_includes_exclude_path(self):
        """Test that LogPathAdmin includes exclude_path in list_display."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        assert "exclude_path" in admin_obj.list_display

    def test_logpath_admin_list_filter_includes_exclude_path(self):
        """Test that LogPathAdmin includes exclude_path in list_filter."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        assert "exclude_path" in admin_obj.list_filter

    def test_logpath_admin_exclude_path_not_readonly_for_existing_objects(self):
        """Test that exclude_path is not readonly for existing objects."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory()
        readonly_fields = admin_obj.get_readonly_fields(None, obj=path)
        assert "exclude_path" not in readonly_fields


@pytest.mark.django_db
class TestBackwardCompatibility:
    """Test backward compatibility with settings-based exclusion."""

    def test_settings_based_bot_exclusion_still_works(self, settings):
        """Test that AUDIT_LOG_EXCLUDE_BOTS setting still works when database field is False."""
        settings.AUDIT_LOG_EXCLUDE_BOTS = True

        # Create a bot user agent with exclude_agent=False
        user_agent = LogUserAgentFactory(is_bot=True, exclude_agent=False)

        # Create a mock request
        request = HttpRequest()
        request.path = "/test/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": user_agent.user_agent,
            "REMOTE_ADDR": "127.0.0.1",
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the user agent lookup
        original_method = LogUserAgent.from_user_agent_string
        LogUserAgent.from_user_agent_string = classmethod(lambda cls, ua: user_agent)

        try:
            # Should still be excluded due to settings
            result = AccessLog.from_request(request)
            assert result is None
        finally:
            LogUserAgent.from_user_agent_string = original_method

    def test_database_exclusion_overrides_settings(self, settings):
        """Test that database exclude_agent=True works even when AUDIT_LOG_EXCLUDE_BOTS=False."""
        settings.AUDIT_LOG_EXCLUDE_BOTS = False

        # Create a non-bot user agent with exclude_agent=True
        user_agent = LogUserAgentFactory(is_bot=False, exclude_agent=True)

        # Create a mock request
        request = HttpRequest()
        request.path = "/test/path"
        request.method = "GET"
        request.META = {
            "HTTP_USER_AGENT": user_agent.user_agent,
            "REMOTE_ADDR": "127.0.0.1",
        }
        request.user = types.SimpleNamespace(
            is_anonymous=True, pk=0, get_username=lambda: "anonymous"
        )
        request.session = types.SimpleNamespace(session_key="test_session")

        # Mock the user agent lookup
        original_method = LogUserAgent.from_user_agent_string
        LogUserAgent.from_user_agent_string = classmethod(lambda cls, ua: user_agent)

        try:
            # Should be excluded due to database setting
            result = AccessLog.from_request(request)
            assert result is None
        finally:
            LogUserAgent.from_user_agent_string = original_method


@pytest.mark.django_db
class TestDetailPageActions:
    """Test detail page actions functionality."""

    def test_detail_actions_mixin_get_detail_actions_default(self):
        """Test that DetailActionsAdminMixin returns empty list by default."""
        from django_audit_log.admin import DetailActionsAdminMixin

        class TestAdmin(DetailActionsAdminMixin):
            pass

        admin_obj = TestAdmin()
        obj = LogUserFactory()
        actions = admin_obj.get_detail_actions(obj)
        assert actions == []

    def test_loguser_admin_detail_actions(self):
        """Test that LogUserAdmin provides detail actions."""
        admin_obj = audit_admin.LogUserAdmin(LogUser, site)
        user = LogUserFactory()

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(user)
        assert len(actions) == 1
        assert actions[0]["name"] == "delete_logs"
        assert "Delete All Logs" in actions[0]["label"]
        assert actions[0]["css_class"] == "deletelink"

    def test_logpath_admin_detail_actions_excluded(self):
        """Test that LogPathAdmin provides correct actions for excluded path."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory(exclude_path=True)

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(path)
        assert len(actions) == 2

        # Find delete action
        delete_action = next(a for a in actions if a["name"] == "delete_logs")
        assert "Delete All Logs" in delete_action["label"]
        assert delete_action["css_class"] == "deletelink"

        # Find include action
        include_action = next(a for a in actions if a["name"] == "include_path")
        assert "Include This Path" in include_action["label"]
        assert include_action["css_class"] == "addlink"

    def test_logpath_admin_detail_actions_included(self):
        """Test that LogPathAdmin provides correct actions for included path."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory(exclude_path=False)

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(path)
        assert len(actions) == 2

        # Find exclude action
        exclude_action = next(a for a in actions if a["name"] == "exclude_path")
        assert "Exclude This Path" in exclude_action["label"]
        assert exclude_action["css_class"] == "default"

    def test_loguseragent_admin_detail_actions_excluded(self):
        """Test that LogUserAgentAdmin provides correct actions for excluded agent."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        agent = LogUserAgentFactory(
            exclude_agent=True, browser="Chrome", browser_version="91.0"
        )

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(agent)
        assert len(actions) == 2

        # Find include action
        include_action = next(a for a in actions if a["name"] == "include_agent")
        assert "Include This User Agent" in include_action["label"]
        assert include_action["css_class"] == "addlink"

    def test_loguseragent_admin_detail_actions_included(self):
        """Test that LogUserAgentAdmin provides correct actions for included agent."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        agent = LogUserAgentFactory(
            exclude_agent=False, browser="Firefox", browser_version="89.0"
        )

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(agent)
        assert len(actions) == 2

        # Find exclude action
        exclude_action = next(a for a in actions if a["name"] == "exclude_agent")
        assert "Exclude This User Agent" in exclude_action["label"]
        assert exclude_action["css_class"] == "default"


@pytest.mark.django_db
class TestDetailActionHandlers:
    """Test detail page action handlers via changeform_view."""

    def test_loguser_delete_logs_action_handler(self):
        """Test LogUserAdmin delete logs action via changeform_view."""
        admin_obj = audit_admin.LogUserAdmin(LogUser, site)
        user = LogUserFactory()

        # Create some access logs for the user
        AccessLogFactory(user=user)
        AccessLogFactory(user=user)

        # Verify logs exist
        assert AccessLog.objects.filter(user=user).count() == 2

        # Mock request for POST with delete_logs action
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/loguser/{user.id}/change/", {"delete_logs": ""}
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Test the changeform_view with delete_logs action
        # This should redirect, so we expect a redirect response
        from django.http import HttpResponseRedirect

        response = admin_obj.changeform_view(request, str(user.id))
        assert isinstance(response, HttpResponseRedirect)

        # Verify logs were deleted
        assert AccessLog.objects.filter(user=user).count() == 0

    def test_logpath_exclude_path_action_handler(self):
        """Test LogPathAdmin exclude path action via changeform_view."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory(exclude_path=False)

        # Mock request for POST with exclude_path action
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/logpath/{path.id}/change/", {"exclude_path": ""}
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Test the changeform_view with exclude_path action
        from django.http import HttpResponseRedirect

        response = admin_obj.changeform_view(request, str(path.id))
        assert isinstance(response, HttpResponseRedirect)

        # Verify path is now excluded
        path.refresh_from_db()
        assert path.exclude_path is True

    def test_logpath_include_path_action_handler(self):
        """Test LogPathAdmin include path action via changeform_view."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory(exclude_path=True)

        # Mock request for POST with exclude_path action (toggles)
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/logpath/{path.id}/change/", {"exclude_path": ""}
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Test the changeform_view with exclude_path action (should toggle to include)
        from django.http import HttpResponseRedirect

        response = admin_obj.changeform_view(request, str(path.id))
        assert isinstance(response, HttpResponseRedirect)

        # Verify path is now included
        path.refresh_from_db()
        assert path.exclude_path is False

    def test_loguseragent_exclude_agent_action_handler(self):
        """Test LogUserAgentAdmin exclude agent action via changeform_view."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        agent = LogUserAgentFactory(exclude_agent=False, browser="Safari")

        # Mock request for POST with exclude_agent action
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/loguseragent/{agent.id}/change/",
            {"exclude_agent": ""},
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Test the changeform_view with exclude_agent action
        from django.http import HttpResponseRedirect

        response = admin_obj.changeform_view(request, str(agent.id))
        assert isinstance(response, HttpResponseRedirect)

        # Verify agent is now excluded
        agent.refresh_from_db()
        assert agent.exclude_agent is True

    def test_loguseragent_include_agent_action_handler(self):
        """Test LogUserAgentAdmin include agent action via changeform_view."""
        admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, site)
        agent = LogUserAgentFactory(exclude_agent=True, browser="Edge")

        # Mock request for POST with exclude_agent action (toggles)
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/loguseragent/{agent.id}/change/",
            {"exclude_agent": ""},
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Test the changeform_view with exclude_agent action (should toggle to include)
        from django.http import HttpResponseRedirect

        response = admin_obj.changeform_view(request, str(agent.id))
        assert isinstance(response, HttpResponseRedirect)

        # Verify agent is now included
        agent.refresh_from_db()
        assert agent.exclude_agent is False


@pytest.mark.django_db
class TestDetailActionPermissions:
    """Test detail page action permissions."""

    def test_detail_actions_respect_permissions(self):
        """Test that detail actions respect user permissions."""
        admin_obj = audit_admin.LogUserAdmin(LogUser, site)
        user = LogUserFactory()

        # Mock request without permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: False
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(user)
        assert len(actions) == 0  # No actions should be available without permissions

    def test_detail_actions_with_permissions(self):
        """Test that detail actions are available with proper permissions."""
        admin_obj = audit_admin.LogPathAdmin(LogPath, site)
        path = LogPathFactory()

        # Mock request with permissions
        import types

        mock_request = types.SimpleNamespace()
        mock_request.user = types.SimpleNamespace()
        mock_request.user.has_perm = lambda perm: True
        mock_request.user.is_superuser = False
        admin_obj.request = mock_request

        actions = admin_obj.get_detail_actions(path)
        assert len(actions) == 2  # Should have both delete and exclude/include actions


@pytest.mark.django_db
class TestDetailActionErrorHandling:
    """Test error handling in detail actions."""

    def test_delete_logs_action_handles_database_error(self):
        """Test that delete logs action handles database errors gracefully."""
        admin_obj = audit_admin.LogUserAdmin(LogUser, site)
        user = LogUserFactory()

        # Mock request for POST with delete_logs action
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.messages.storage.fallback import FallbackStorage
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.test import RequestFactory

        factory = RequestFactory()
        request = factory.post(
            f"/admin/django_audit_log/loguser/{user.id}/change/", {"delete_logs": ""}
        )
        request.user = AnonymousUser()
        request.user.is_superuser = True
        request.user.has_perm = lambda perm: True

        # Add session and messages
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        request.session.save()

        request._messages = FallbackStorage(request)

        # Mock AccessLog.objects.filter to raise an exception
        original_filter = AccessLog.objects.filter

        def mock_filter(*args, **kwargs):
            raise Exception("Database error")

        AccessLog.objects.filter = mock_filter

        try:
            # Test the changeform_view with delete_logs action
            # Should handle the error gracefully and redirect
            from django.http import HttpResponseRedirect

            response = admin_obj.changeform_view(request, str(user.id))
            assert isinstance(response, HttpResponseRedirect)

            # Check that an error message was added
            messages = list(request._messages)
            assert len(messages) >= 1
            # Look for error message in the messages
            error_found = any("Error deleting" in str(msg.message) for msg in messages)
            assert error_found, f"Expected error message not found in: {[str(msg.message) for msg in messages]}"

        finally:
            # Restore original method
            AccessLog.objects.filter = original_filter
