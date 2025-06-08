# Database-Based Exclusion Features

## Overview

Django Audit Log now supports database-configurable exclusion rules in addition to the existing settings-based exclusion. This allows administrators to manage exclusion rules through the Django Admin interface without requiring code changes or deployments.

## What's New

### 1. Database Fields

Two new boolean fields have been added to control exclusion behavior:

- **`LogUserAgent.exclude_agent`**: When `True`, prevents any requests using this user agent from being logged
- **`LogPath.exclude_path`**: When `True`, prevents any requests to this URL path from being logged

### 2. Admin Interface Enhancements

#### User Agent Admin (`LogUserAgent`)
- ✅ **New field in list view**: `exclude_agent` column shows exclusion status
- ✅ **New filter**: Filter by excluded/included user agents
- ✅ **Editable field**: Click to toggle exclusion for any user agent
- ✅ **New admin action**: "Delete access log records for selected user agents"

#### Path Admin (`LogPath`)
- ✅ **New field in list view**: `exclude_path` column shows exclusion status
- ✅ **New filter**: Filter by excluded/included paths
- ✅ **Editable field**: Click to toggle exclusion for any path
- ✅ **New admin action**: "Delete access log records for selected paths"

#### User Admin (`LogUser`)
- ✅ **New admin action**: "Delete access log records for selected users"

## How It Works

### Exclusion Priority Order

Database exclusion takes **precedence** over settings-based exclusion:

1. **Database exclusion** (highest priority)
   - `LogUserAgent.exclude_agent = True` → Request blocked
   - `LogPath.exclude_path = True` → Request blocked

2. **Settings-based exclusion** (lower priority)
   - `AUDIT_LOG_EXCLUDE_BOTS = True` → Bot requests blocked
   - `AUDIT_LOG_EXCLUDED_URLS` patterns → Matching URLs blocked

3. **Normal logging** (if no exclusions match)

### Example Scenarios

```python
# Scenario 1: Database exclusion overrides settings
# Settings: AUDIT_LOG_EXCLUDE_BOTS = False
# Database: Chrome user agent has exclude_agent = True
# Result: Chrome requests are blocked (database wins)

# Scenario 2: Backward compatibility maintained
# Settings: AUDIT_LOG_EXCLUDE_BOTS = True
# Database: Googlebot has exclude_agent = False
# Result: Googlebot requests are blocked (settings still apply)

# Scenario 3: Multiple exclusions
# Database: /api/health has exclude_path = True
# Settings: AUDIT_LOG_EXCLUDED_URLS = [r"^/api/.*"]
# Result: All /api/* paths blocked by settings, /api/health also blocked by database
```

## Usage Guide

### 1. Managing User Agent Exclusions

**Via Django Admin:**
1. Go to `Django Audit Log → Log User Agents`
2. Find the user agent you want to exclude
3. Check the `Exclude Agent` checkbox
4. Save the changes

**Bulk Operations:**
1. Select multiple user agents using checkboxes
2. Choose "Delete access log records for selected user agents" from actions dropdown
3. Click "Go" to execute

### 2. Managing Path Exclusions

**Via Django Admin:**
1. Go to `Django Audit Log → Log Paths`
2. Find the path you want to exclude
3. Check the `Exclude This URL` checkbox
4. Save the changes

**Bulk Operations:**
1. Select multiple paths using checkboxes
2. Choose "Delete access log records for selected paths" from actions dropdown
3. Click "Go" to execute

### 3. Managing User Record Cleanup

**Via Django Admin:**
1. Go to `Django Audit Log → Log Users`
2. Select users whose records you want to delete
3. Choose "Delete access log records for selected users" from actions dropdown
4. Click "Go" to execute

## Migration Information

### Database Changes

The following migration was created: `0009_logpath_exclude_path_loguseragent_exclude_agent_and_more.py`

**What it adds:**
- `LogPath.exclude_path` field (default: `False`)
- `LogUserAgent.exclude_agent` field (default: `False`)
- Database indexes for performance

**Migration Command:**
```bash
python manage.py migrate django_audit_log
```

**Safe to run in production:** ✅ Yes - only adds new fields with safe defaults

### Backward Compatibility

✅ **Fully backward compatible** - existing functionality unchanged
✅ **Settings still work** - `AUDIT_LOG_EXCLUDE_BOTS` and `AUDIT_LOG_EXCLUDED_URLS` continue to function
✅ **No breaking changes** - all existing code continues to work

## Performance Considerations

### Database Indexes

New indexes were added for optimal performance:
```sql
-- Indexes added automatically by migration
CREATE INDEX django_audi_exclude_5712fd_idx ON django_audit_log_logpath (exclude_path);
CREATE INDEX django_audi_exclude_879cbc_idx ON django_audit_log_loguseragent (exclude_agent);
```

### Query Impact

Database exclusion checks add minimal overhead:
- **User agent check**: Single indexed boolean lookup per request
- **Path check**: Single indexed boolean lookup per request
- **Early exit**: Excluded requests short-circuit before heavy processing

## Code Examples

### Checking Exclusion Status Programmatically

```python
from django_audit_log.models import LogUserAgent, LogPath

# Check if a user agent is excluded
user_agent = LogUserAgent.objects.get(user_agent="Chrome/91.0...")
if user_agent.exclude_agent:
    print("This user agent is excluded from logging")

# Check if a path is excluded
path = LogPath.objects.get(path="/api/health")
if path.exclude_path:
    print("This path is excluded from logging")

# Get all excluded user agents
excluded_agents = LogUserAgent.objects.filter(exclude_agent=True)

# Get all excluded paths
excluded_paths = LogPath.objects.filter(exclude_path=True)
```

### Bulk Exclusion Operations

```python
# Exclude all bot user agents
LogUserAgent.objects.filter(is_bot=True).update(exclude_agent=True)

# Exclude all admin paths
LogPath.objects.filter(path__startswith='/admin/').update(exclude_path=True)

# Re-include specific paths
LogPath.objects.filter(path='/admin/login/').update(exclude_path=False)
```

## Testing

### Running Feature Tests

```bash
# Test database exclusion functionality
python -m pytest src/django_audit_log/tests.py::TestDatabaseExclusion -v

# Test admin actions
python -m pytest src/django_audit_log/tests.py::TestAdminActions -v

# Test admin interface changes
python -m pytest src/django_audit_log/tests.py::TestAdminInterfaceChanges -v

# Test backward compatibility
python -m pytest src/django_audit_log/tests.py::TestBackwardCompatibility -v

# Run all new feature tests
python -m pytest src/django_audit_log/tests.py -k "TestDatabase or TestAdmin or TestBackward" -v
```

## Troubleshooting

### Common Issues

**Q: My exclusions aren't working**
A: Check that the database migration has been applied: `python manage.py showmigrations django_audit_log`

**Q: Settings-based exclusion stopped working**
A: Database exclusion takes precedence. Check if the user agent/path has `exclude_agent`/`exclude_path` set to `False` in the database.

**Q: Performance concerns with large datasets**
A: The new fields are indexed. If you have millions of records, consider adding exclusions in batches during low-traffic periods.

### Debug Commands

```bash
# Check migration status
python manage.py showmigrations django_audit_log

# Verify new fields exist
python manage.py shell
>>> from django_audit_log.models import LogUserAgent, LogPath
>>> LogUserAgent._meta.get_field('exclude_agent')
>>> LogPath._meta.get_field('exclude_path')

# Check index creation
python manage.py sqlmigrate django_audit_log 0009
```

## Benefits

1. **Dynamic Configuration**: Change exclusion rules without code deployments
2. **Granular Control**: Exclude specific user agents or paths, not just patterns
3. **Admin Interface**: User-friendly management through Django Admin
4. **Bulk Operations**: Delete historical records with admin actions
5. **Backward Compatible**: Existing settings-based exclusion continues to work
6. **Performance**: Database indexes ensure fast exclusion checks
7. **Audit Trail**: All exclusion changes are tracked through Django Admin

## Next Steps

1. **Review existing exclusions**: Migrate important `AUDIT_LOG_EXCLUDED_URLS` patterns to database
2. **Train administrators**: Show team how to use new Admin interface features
3. **Monitor performance**: Watch for any performance impact in production
4. **Consider automation**: Build scripts for common exclusion patterns
5. **Clean up old data**: Use new admin actions to remove unwanted historical records
