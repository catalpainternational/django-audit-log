import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.admin.sites import site
import factory
from .models import LogUser, AccessLog

def test_stub_math():
    assert 1 + 1 == 2 

@pytest.mark.django_db
def test_admin_pages_accessible(admin_client):
    # Get all registered models
    for model, model_admin in site._registry.items():
        app_label = model._meta.app_label
        model_name = model._meta.model_name
        url = reverse(f'admin:{app_label}_{model_name}_changelist')
        response = admin_client.get(url)
        assert response.status_code == 200, f"Admin page for {model.__name__} not accessible" 

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
        model = 'django_audit_log.LogPath'
    path = factory.Faker('uri_path')

class LogSessionKeyFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = 'django_audit_log.LogSessionKey'
    key = factory.Faker('uuid4')

class LogIpAddressFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = 'django_audit_log.LogIpAddress'
    address = factory.Faker('ipv4')

class LogUserAgentFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = 'django_audit_log.LogUserAgent'
    user_agent = factory.Faker('user_agent')
    browser = factory.Faker('chrome')
    browser_version = factory.Faker('numerify', text='##.0')
    operating_system = factory.Faker('linux_platform_token')
    operating_system_version = factory.Faker('numerify', text='##.##')
    device_type = factory.Iterator(['Desktop', 'Mobile', 'Tablet'])
    is_bot = False

@pytest.mark.django_db
def test_logpath_factory():
    obj = LogPathFactory()
    from .models import LogPath
    assert LogPath.objects.filter(pk=obj.pk).exists()

@pytest.mark.django_db
def test_logsessionkey_factory():
    obj = LogSessionKeyFactory()
    from .models import LogSessionKey
    assert LogSessionKey.objects.filter(pk=obj.pk).exists()

@pytest.mark.django_db
def test_logipaddress_factory():
    obj = LogIpAddressFactory()
    from .models import LogIpAddress
    assert LogIpAddress.objects.filter(pk=obj.pk).exists()

@pytest.mark.django_db
def test_loguseragent_factory():
    obj = LogUserAgentFactory()
    from .models import LogUserAgent
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