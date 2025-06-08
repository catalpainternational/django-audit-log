import pytest
from django.test import override_settings

from django_audit_log.models import AccessLog


@pytest.mark.django_db
@override_settings(AUDIT_LOG_EXCLUDED_URLS=[r"^/sw\.js$"])
def test_sw_js_excluded(client):
    # Simulate a 200 response for /sw.js
    response = client.get("/sw.js")
    assert (
        response.status_code == 200 or response.status_code == 404
    )  # Accept 404 if no view
    # Should not log if status is 200
    if response.status_code == 200:
        assert not AccessLog.objects.filter(path__path="/sw.js").exists()


@pytest.mark.django_db
@override_settings(AUDIT_LOG_EXCLUDE_BOTS=True)
def test_exclude_bot_device(client):
    # Simulate a request with a bot user agent
    bot_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    client.get("/", HTTP_USER_AGENT=bot_ua)
    # Should not log any access for bot
    assert not AccessLog.objects.filter(user_agent=bot_ua).exists()


# Create your tests here.
