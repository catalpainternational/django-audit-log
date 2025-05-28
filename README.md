# django-audit-log

A Django application for logging HTTP requests and responses.

## Installation

```bash
pip install django-audit-log
```

Add `django_audit_log` to your `INSTALLED_APPS` setting:

```python
INSTALLED_APPS = [
    # ...
    'django_audit_log',
    # ...
]
```

Add "django_audit_log.middleware.AuditLogMiddleware" to your `MIDDLEWARE` setting
```python
MIDDLEWARE = [
    # ...
    "django_audit_log.middleware.AuditLogMiddleware",
    # ...
]
```


## Features

- Logs HTTP requests and responses
- Tracks user, session, IP, and user agent information
- Normalizes and categorizes user agent data
- Configurable sampling to reduce database usage
- Includes sampling metadata for audit trail completeness

## Configuration

### IP Address Exclusion

You can configure certain IP addresses to be excluded from logging entirely:

```python
# IP addresses that will never be logged (default: ["127.0.0.1"])
AUDIT_LOG_EXCLUDED_IPS = [
    "127.0.0.1",      # Local development
    "10.0.0.5",       # Internal monitoring service
    "192.168.1.100",  # Load balancer health checks
]
```

Requests from these IP addresses will be completely ignored by the audit log system. This is useful for:
- Excluding local development traffic
- Ignoring health check requests
- Preventing monitoring service requests from being logged

### Sampling Configuration

To limit database usage, you can configure which URLs are logged and at what sampling rate:

```python
# Set the sampling rate for URLs in the sampling list (default: 1.0 = 100%)
AUDIT_LOG_SAMPLE_RATE = 0.25

# URLs that will ALWAYS be logged (no sampling applied)
AUDIT_LOG_ALWAYS_LOG_URLS = [
    r'^/admin/.*',    # Always log admin URLs
    r'^/checkout/.*', # Always log checkout process
]

# URLs that will be SAMPLED at the configured sample rate
AUDIT_LOG_SAMPLE_URLS = [
    r'^/api/v1/.*',      # Sample API calls
    r'^/products/.*',    # Sample product pages
]
```

The logging behavior follows these rules:

1. URLs matching patterns in `AUDIT_LOG_ALWAYS_LOG_URLS` will always be logged (100%)
2. URLs matching patterns in `AUDIT_LOG_SAMPLE_URLS` will be logged based on the sample rate
3. All other URLs will never be logged

If neither URL list is defined, the system will fall back to sampling all URLs at the configured rate for backward compatibility.

### Sampling Metadata Fields

Each `AccessLog` entry includes the following sampling metadata fields to provide a complete audit trail:

- `in_always_log_urls`: Boolean indicating whether the URL matched a pattern in `AUDIT_LOG_ALWAYS_LOG_URLS`
- `in_sample_urls`: Boolean indicating whether the URL matched a pattern in `AUDIT_LOG_SAMPLE_URLS`
- `sample_rate`: The value of `AUDIT_LOG_SAMPLE_RATE` at the time the log was created

These fields are useful for:

- Understanding why a particular request was logged
- Analyzing the completeness of your audit logs
- Estimating the total traffic based on sampled logs
- Fine-tuning your sampling configuration

### Example Sampling Configurations

#### High-Volume Production Site

For high-traffic websites wanting to minimize database usage while still capturing critical events:

```python
# Very low sample rate to minimize DB usage
AUDIT_LOG_SAMPLE_RATE = 0.05  # Only sample 5% of eligible requests

# Always log security-critical operations
AUDIT_LOG_ALWAYS_LOG_URLS = [
    r'^/admin/.*',             # Admin panel activity
    r'^/api/v1/payment/.*',    # Payment processing
    r'^/auth/login.*',         # Login attempts
    r'^/auth/password/reset.*', # Password resets
]

# Sample a small percentage of regular user activity
AUDIT_LOG_SAMPLE_URLS = [
    r'^/api/.*',               # API calls
    r'^/user/profile/.*',      # User profile activity
]
```

#### Security-Focused Configuration

For applications where security auditing is a priority:

```python
# Higher sampling rate for security monitoring
AUDIT_LOG_SAMPLE_RATE = 0.3  # Sample 30% of eligible requests

# Always log security-sensitive paths
AUDIT_LOG_ALWAYS_LOG_URLS = [
    r'^/admin/.*',             # Admin actions
    r'^/auth/.*',              # All authentication activity
    r'^/api/v1/users/.*',      # User management API
    r'^/settings/.*',          # Account settings changes
    r'^/billing/.*',           # Billing information
]

# Sample other important user interactions
AUDIT_LOG_SAMPLE_URLS = [
    r'^/api/.*',               # Other API endpoints
    r'^/download/.*',          # File downloads
    r'^/upload/.*',            # File uploads
]
```

#### Development Environment

For development environments, you might want more comprehensive logging:

```python
# Full sampling in development for debugging
AUDIT_LOG_SAMPLE_RATE = 1.0  # 100% sampling

# Critical paths to always check during development
AUDIT_LOG_ALWAYS_LOG_URLS = [
    r'^/admin/.*',            # Admin functionality
]

# Log most application paths for debugging
AUDIT_LOG_SAMPLE_URLS = [
    r'^/api/.*',              # API endpoints
    r'^/.*',                  # All other paths
]
```

#### Minimal Configuration

For applications with basic logging needs:

```python
# Sample 10% of regular traffic
AUDIT_LOG_SAMPLE_RATE = 0.1

# Only always log admin actions
AUDIT_LOG_ALWAYS_LOG_URLS = [
    r'^/admin/.*',
]

# Sample user account-related activities
AUDIT_LOG_SAMPLE_URLS = [
    r'^/user/.*',
    r'^/account/.*',
]
```

## Usage

The simplest way to use django-audit-log is to include the AccessLogMiddleware in your middleware settings:

```python
MIDDLEWARE = [
    # ...
    'django_audit_log.middleware.AccessLogMiddleware',
    # ...
]
```

## Management Commands

### reimport_user_agents

This command reprocesses all user agents in the database using the current parsing logic. This is useful when you've updated the user agent parsing rules and want to apply them to existing records.

```bash
# Reprocess all user agents with default batch size (1000)
python manage.py reimport_user_agents

# Specify a custom batch size
python manage.py reimport_user_agents --batch-size 500
```

The command will display progress and provide a summary of the results, including:
- Total number of user agents processed
- Number of user agents that were updated
- Number of user agents that remained unchanged

## Using in Views

You can use the AccessLogMixin in your views:

```python
from django_audit_log.mixins import AccessLogMixin
from django.views.generic import DetailView

class MyView(AccessLogMixin, DetailView):
    # Your view code here
    pass
```

Or manually log requests:

```python
from django_audit_log.models import AccessLog

def my_view(request):
    # Your view code here
    response = HttpResponse('Hello, world!')
    AccessLog.from_request(request, response)
    return response
```
