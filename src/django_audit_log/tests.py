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
    ua = LogUserAgentFactory()
    user = LogUserFactory()
    _log = AccessLogFactory(user_agent_normalized=ua, user=user)
    admin_obj = audit_admin.LogUserAgentAdmin(LogUserAgent, admin.site)
    html = admin_obj.related_users(ua)
    assert "user-list" in html or "No users have used this user agent" in html
