# Database-Based Exclusion Features

This document details the implementation of database-configurable exclusion rules for the Django Audit Log system, replacing or supplementing the settings-based exclusion patterns.

## Architecture Overview

### Detail Page Actions vs Bulk Actions

**Design Decision: We use individual detail page actions instead of bulk admin actions.**

**Rationale:**
- **Precision**: Each record can be individually reviewed before exclusion/deletion
- **Safety**: Reduces risk of accidentally excluding/deleting large datasets
- **User Experience**: Clear context about what will be affected
- **Permissions**: Granular permission checking per record
- **Audit Trail**: Better tracking of who excluded/deleted what and when

**What this means:**
- ✅ Actions available on individual record detail pages (e.g., `/admin/django_audit_log/logpath/123/change/`)
- ❌ No bulk actions in the admin list view for exclusion/deletion
- ✅ Bulk operations still possible via Django's built-in delete actions
- ✅ Custom management commands for bulk operations when needed

### Implementation Details

The detail page actions are implemented via:
1. **DetailActionsAdminMixin**: Provides the framework for adding action buttons to change forms
2. **Admin Templates**: Custom templates render the action buttons in the change form
3. **changeform_view Override**: Handles POST requests from action buttons
4. **Permission Checking**: Each action verifies user permissions before execution

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
- ✅ **Detail page actions**: Individual record actions for delete logs and toggle exclusion

#### Path Admin (`LogPath`)
- ✅ **New field in list view**: `exclude_path` column shows exclusion status
- ✅ **New filter**: Filter by excluded/included paths
- ✅ **Editable field**: Click to toggle exclusion for any path
- ✅ **New admin action**: "Delete access log records for selected paths"
- ✅ **Detail page actions**: Individual record actions for delete logs and toggle exclusion

#### User Admin (`LogUser`)
- ✅ **New admin action**: "Delete access log records for selected users"
- ✅ **Detail page actions**: Individual record actions for delete logs

### 3. Detail Page Actions

Each admin detail/change page now includes additional action buttons:

**For Users (`LogUser`):**
- 🗑️ **Delete All Logs for User**: Removes all access log records for the specific user

**For Paths (`LogPath`):**
- 🗑️ **Delete All Logs for Path**: Removes all access log records for the specific path
- 🔄 **Toggle Path Exclusion**: Include/exclude the path from future logging

**For User Agents (`LogUserAgent`):**
- 🗑️ **Delete All Logs for User Agent**: Removes all access log records for the specific user agent
- 🔄 **Toggle Agent Exclusion**: Include/exclude the user agent from future logging

**Features:**
- ✅ **Confirmation dialogs**: Destructive actions require confirmation
- ✅ **Permission-based**: Actions only appear for users with appropriate permissions
- ✅ **Success/error messaging**: Clear feedback on action results
- ✅ **Transaction safety**: Database operations are wrapped in transactions

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

**Via Django Admin List View:**
1. Go to `Django Audit Log → Log User Agents`
2. Find the user agent you want to exclude
3. Check the `Exclude Agent` checkbox
4. Save the changes

**Via Detail Page Actions:**
1. Go to `Django Audit Log → Log User Agents`
2. Click on a specific user agent to view its details
3. Scroll to the "Additional Actions" section at the bottom
4. Click "Exclude This User Agent from Logging" or "Include This User Agent in Logging"
5. Click "Delete All Logs for User Agent" to remove historical records (requires confirmation)

**Bulk Operations:**
1. Select multiple user agents using checkboxes
2. Choose "Delete access log records for selected user agents" from actions dropdown
3. Click "Go" to execute

### 2. Managing Path Exclusions

**Via Django Admin List View:**
1. Go to `Django Audit Log → Log Paths`
2. Find the path you want to exclude
3. Check the `Exclude This URL` checkbox
4. Save the changes

**Via Detail Page Actions:**
1. Go to `Django Audit Log → Log Paths`
2. Click on a specific path to view its details
3. Scroll to the "Additional Actions" section at the bottom
4. Click "Exclude This Path from Logging" or "Include This Path in Logging"
5. Click "Delete All Logs for Path" to remove historical records (requires confirmation)

**Bulk Operations:**
1. Select multiple paths using checkboxes
2. Choose "Delete access log records for selected paths" from actions dropdown
3. Click "Go" to execute

### 3. Managing User Record Cleanup

**Via Detail Page Actions:**
1. Go to `Django Audit Log → Log Users`
2. Click on a specific user to view their details
3. Scroll to the "Additional Actions" section at the bottom
4. Click "Delete All Logs for User" to remove all records for this user (requires confirmation)

**Via Bulk Operations:**
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
