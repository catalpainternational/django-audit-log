import pytest
from django.test import Client
from django.conf import settings
from django_audit_log.models import AccessLog

@pytest.mark.django_db
def test_gather_admin_excluded():
    client = Client()
    response = client.get('/gather/gather_admin/')
    assert response.status_code == 200
    # There should be no AccessLog entry for this path
    assert not AccessLog.objects.filter(path__path='/gather/gather_admin/').exists()

@pytest.mark.django_db
def test_sw_js_excluded(client, settings):
    settings.AUDIT_LOG_EXCLUDED_URLS = [r"^/sw\\.js$"]
    # Simulate a 200 response for /sw.js
    response = client.get("/sw.js")
    assert response.status_code == 200 or response.status_code == 404  # Accept 404 if no view
    # Should not log if status is 200
    if response.status_code == 200:
        assert not AccessLog.objects.filter(path__path="/sw.js").exists()

@pytest.mark.django_db
def test_exclude_bot_device(client, settings):
    settings.AUDIT_LOG_EXCLUDE_BOTS = True
    # Simulate a request with a bot user agent
    bot_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    response = client.get("/", HTTP_USER_AGENT=bot_ua)
    # Should not log any access for bot
    assert not AccessLog.objects.filter(user_agent=bot_ua).exists()

# Create your tests here.
