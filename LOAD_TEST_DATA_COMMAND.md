# Load Test Data Management Command

## Overview

The `load_test_data` management command creates realistic test data for the Django Audit Log system. This is useful for development, testing, and demo purposes.

## Usage

```bash
# Basic usage with default values
python manage.py load_test_data

# Custom parameters
python manage.py load_test_data --urls 20 --audit-logs 5000 --users 10 --admin-users 2

# Clean existing data first
python manage.py load_test_data --clean

# Show help
python manage.py load_test_data --help
```

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--urls` | 10 | Number of unique URL paths to create |
| `--audit-logs` | 10,000 | Number of audit log entries to create |
| `--users` | 5 | Number of regular users to create |
| `--admin-users` | 1 | Number of admin users to create |
| `--clean` | False | Delete existing test data before creating new data |
| `--batch-size` | 500 | Batch size for creating audit logs (performance tuning) |

## What Gets Created

### 1. Django Users
- **Regular users**: `testuser1`, `testuser2`, etc. (password: `testpass123`)
- **Admin users**: `admin1`, `admin2`, etc. (password: `adminpass123`)
- All users have realistic names and email addresses

### 2. URL Paths (LogPath)
Common web application paths including:
- `/`, `/home/`, `/about/`, `/contact/`
- `/login/`, `/logout/`, `/admin/`
- `/api/users/`, `/api/posts/`, `/api/comments/`
- `/dashboard/`, `/profile/`, `/settings/`
- Additional paths if more than 20 are requested

**Features:**
- ~10% of paths are randomly marked as excluded
- Realistic web application URL structure

### 3. User Agents (LogUserAgent)
Common user agent strings for:
- **Desktop browsers**: Chrome, Firefox, Safari on Windows/Mac/Linux
- **Mobile browsers**: Mobile Safari, Chrome Mobile, Firefox Mobile
- **Search bots**: Googlebot, Bingbot

**Features:**
- ~20% of user agents are randomly marked as excluded
- Proper parsing of browser, OS, and device information
- Mix of regular browsers and bots

### 4. IP Addresses (LogIpAddress)
- **Private IP ranges**: 192.168.1.x, 10.0.0.x, 172.16.0.x
- **Test IP ranges**: 203.0.113.x, 198.51.100.x
- 100 unique IP addresses by default

### 5. Session Keys (LogSessionKey)
- 50 unique session keys with UUID format
- Realistic session key patterns

### 6. Audit Logs (AccessLog)
Realistic audit log entries with:

**Request Details:**
- **Methods**: GET, POST, PUT, DELETE, PATCH
- **Status codes**: Weighted towards success (200, 201) with some errors
- **Timestamps**: Distributed over the last 30 days
- **Request data**: Varied JSON payloads (searches, form data, API calls)

**Relationships:**
- **80% have users** (20% anonymous)
- **90% have session keys** (10% without sessions)
- **70% have referrers** (30% direct access)
- **30% have response URLs** (redirects)

**Performance Features:**
- Created in configurable batches for memory efficiency
- Progress reporting during creation
- Database transaction safety

## Example Output

```
Cleaning existing test data...
Cleaned existing test data
Starting test data creation...
Created 6 users (1 admins, 5 regular)
Created 10 URL paths
Created 10 user agents
Created 100 IP addresses
Created 50 session keys
Created batch 1: 500/10000 audit logs
Created batch 2: 1000/10000 audit logs
...
Created batch 20: 10000/10000 audit logs
Successfully created 10000 audit log entries!

=== Test Data Summary ===
Users: 6
URL Paths: 10
User Agents: 10
IP Addresses: 100
Session Keys: 50
Audit Logs: 10000

Excluded Paths: 2
Excluded User Agents: 2

Django Users: 6
Admin Users: 1

Test data creation completed successfully!
```

## Performance Considerations

### Batch Processing
- Audit logs are created in batches (default: 500 per batch)
- Adjust `--batch-size` based on available memory
- Smaller batches = less memory, more database round trips
- Larger batches = more memory, fewer database round trips

### Database Considerations
- Uses `bulk_create()` for optimal performance
- All operations are wrapped in a database transaction
- Foreign key relationships are efficiently managed

### Recommended Batch Sizes
- **Small datasets** (< 1,000 logs): 100-200
- **Medium datasets** (1,000-10,000 logs): 500 (default)
- **Large datasets** (> 10,000 logs): 1,000-2,000

## Use Cases

### Development
```bash
# Quick setup for development
python manage.py load_test_data --urls 5 --audit-logs 100 --users 2
```

### Testing
```bash
# Test database exclusion features
python manage.py load_test_data --clean
# Some paths and user agents will be excluded automatically
```

### Demo/Presentation
```bash
# Rich dataset for demos
python manage.py load_test_data --urls 20 --audit-logs 5000 --users 10 --admin-users 2
```

### Performance Testing
```bash
# Large dataset for performance testing
python manage.py load_test_data --audit-logs 50000 --batch-size 1000 --clean
```

## Data Characteristics

### Realistic Distribution
- **Request methods**: Weighted towards GET/POST
- **Status codes**: Mostly successful responses (200, 201)
- **Timestamps**: Spread across last 30 days
- **Users**: Mix of authenticated and anonymous requests
- **Exclusions**: Some paths and user agents marked as excluded

### Test Features Coverage
- **Database exclusion**: Tests both `exclude_path` and `exclude_agent` fields
- **Admin interface**: Provides data for all admin list views and filters
- **Relationships**: Tests all foreign key relationships
- **Sampling**: Includes sampling metadata fields
- **Data variety**: JSON request data in various formats

## Cleanup

To remove all test data:
```bash
python manage.py load_test_data --clean --urls 0 --audit-logs 0 --users 0 --admin-users 0
```

Or manually in Django shell:
```python
from django_audit_log.models import *
from django.contrib.auth import get_user_model

# Delete in dependency order
AccessLog.objects.all().delete()
LogSessionKey.objects.all().delete()
LogIpAddress.objects.all().delete()
LogUserAgent.objects.all().delete()
LogPath.objects.all().delete()
LogUser.objects.all().delete()

# Clean Django users
User = get_user_model()
User.objects.filter(username__startswith="testuser").delete()
User.objects.filter(username__startswith="admin").delete()
```

## Integration with Tests

The command can be used in test setups:

```python
from django.core.management import call_command

def setUp(self):
    call_command('load_test_data',
                urls=5,
                audit_logs=50,
                users=2,
                admin_users=1,
                verbosity=0)  # Suppress output in tests
```
