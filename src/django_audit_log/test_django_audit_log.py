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

# Create your tests here.
