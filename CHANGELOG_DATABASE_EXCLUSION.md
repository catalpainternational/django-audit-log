# Changelog: Database-Based Exclusion Features

## Release: Database Exclusion Implementation
**Date:** December 2024
**Type:** Feature Enhancement
**Breaking Changes:** None (Fully backward compatible)

## Summary

Implemented database-configurable exclusion rules for Django Audit Log, allowing administrators to manage exclusion settings through the Django Admin interface without requiring code changes.

## 🆕 New Features

### Database Schema
- **Added `LogUserAgent.exclude_agent`** (BooleanField, default=False)
  - Excludes specific user agents from logging when set to `True`
  - Indexed for performance

- **Added `LogPath.exclude_path`** (BooleanField, default=False)
  - Excludes specific URL paths from logging when set to `True`
  - Indexed for performance

### Admin Interface Enhancements

#### LogUserAgent Admin
- ✅ Added `exclude_agent` to `list_display`
- ✅ Added `exclude_agent` to `list_filter`
- ✅ Made `exclude_agent` field editable (not readonly)
- ✅ Added admin action: "Delete access log records for selected user agents"

#### LogPath Admin
- ✅ Added `exclude_path` to `list_display`
- ✅ Added `exclude_path` to `list_filter`
- ✅ Made `exclude_path` field editable (not readonly)
- ✅ Added admin action: "Delete access log records for selected paths"

#### LogUser Admin
- ✅ Added admin action: "Delete access log records for selected users"

### Business Logic Updates

#### `AccessLog.from_request()` Method
- Database exclusion checks take precedence over settings-based exclusion
- Early exit for excluded user agents (before expensive processing)
- Backward compatibility maintained for `AUDIT_LOG_EXCLUDE_BOTS` setting

#### `AccessLog._check_sampling()` Method
- Database path exclusion checked before settings-based URL patterns
- Early exit for excluded paths (before sampling logic)
- Backward compatibility maintained for `AUDIT_LOG_EXCLUDED_URLS` setting

## 🔧 Technical Changes

### Files Modified

**`src/django_audit_log/models.py`**
- Added `exclude_agent` field to `LogUserAgent` model
- Added `exclude_path` field to `LogPath` model
- Updated `AccessLog.from_request()` to check database exclusions
- Updated `AccessLog._check_sampling()` to check database path exclusions
- Added database indexes for new fields

**`src/django_audit_log/admin.py`**
- Enhanced `LogUserAgentAdmin` with new field and action
- Enhanced `LogPathAdmin` with new field and action
- Enhanced `LogUserAdmin` with new delete action
- Updated `get_readonly_fields()` methods to allow editing exclusion fields

**`src/django_audit_log/tests.py`**
- Added comprehensive test suite for database exclusion (`TestDatabaseExclusion`)
- Added admin action tests (`TestAdminActions`)
- Added admin interface tests (`TestAdminInterfaceChanges`)
- Added backward compatibility tests (`TestBackwardCompatibility`)
- Updated factory classes to support new fields

**`src/django_audit_log/test_django_audit_log.py`**
- Fixed import sorting to resolve linting errors
- Updated to use `@override_settings` decorator (Django best practice)

### Database Migration
- **Created:** `0009_logpath_exclude_path_loguseragent_exclude_agent_and_more.py`
- **Safe for production:** ✅ Yes (only adds new fields with safe defaults)

## 🧪 Testing

### Test Coverage
- **Total new tests:** 22 tests added
- **All existing tests:** ✅ Pass (57/57)
- **Test categories:**
  - Database exclusion functionality
  - Admin action functionality
  - Admin interface changes
  - Backward compatibility

### Test Commands
```bash
# Run all new feature tests
pytest src/django_audit_log/tests.py -k "TestDatabase or TestAdmin or TestBackward" -v

# Run full test suite
pytest src/django_audit_log/tests.py -v
```

## 🔄 Backward Compatibility

✅ **Fully backward compatible**
- All existing settings continue to work (`AUDIT_LOG_EXCLUDE_BOTS`, `AUDIT_LOG_EXCLUDED_URLS`)
- No breaking changes to existing APIs
- Database exclusion enhances rather than replaces settings-based exclusion
- Default values ensure no behavior changes for existing installations

## 📈 Performance Impact

### Minimal Overhead Added
- **User agent check:** Single indexed boolean lookup per request
- **Path check:** Single indexed boolean lookup per request
- **Early exit:** Excluded requests short-circuit expensive processing
- **Database indexes:** Ensure fast lookups on new fields

### Query Examples
```sql
-- Fast indexed lookups added to request processing
SELECT exclude_agent FROM django_audit_log_loguseragent WHERE id = ?;
SELECT exclude_path FROM django_audit_log_logpath WHERE path = ?;
```

## 🎯 Benefits

1. **Dynamic configuration** without code deployments
2. **Granular control** over individual user agents and paths
3. **User-friendly admin interface** for non-technical users
4. **Bulk operations** for managing historical data
5. **Performance optimized** with database indexes
6. **Full backward compatibility** preserves existing functionality

## 📋 Migration Instructions

### For Development
```bash
cd testproject/
python manage.py migrate django_audit_log
```

### For Production
```bash
# 1. Apply the migration (safe - only adds new fields)
python manage.py migrate django_audit_log

# 2. Optional: Review and migrate existing exclusion patterns
python manage.py shell
>>> from django_audit_log.models import LogUserAgent
>>> LogUserAgent.objects.filter(is_bot=True).update(exclude_agent=True)
```

## 🔍 Verification Steps

After deployment, verify the features work:

```bash
# 1. Check migration applied
python manage.py showmigrations django_audit_log

# 2. Verify new fields exist
python manage.py shell
>>> from django_audit_log.models import LogUserAgent, LogPath
>>> LogUserAgent._meta.get_field('exclude_agent')
>>> LogPath._meta.get_field('exclude_path')

# 3. Test admin interface
# Visit /admin/django_audit_log/ and verify new fields and actions are visible
```

## 📚 Documentation

- **Feature documentation:** `DATABASE_EXCLUSION_FEATURES.md`
- **Implementation plan:** `DATABASE_EXCLUSION_IMPLEMENTATION.md`
- **This changelog:** `CHANGELOG_DATABASE_EXCLUSION.md`
