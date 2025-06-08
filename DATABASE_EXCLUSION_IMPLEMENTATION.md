# Database-Based Exclusion Implementation

## Overview

This document outlines the implementation plan for transitioning from Django settings-based exclusion rules to database-configurable exclusion rules for the Django Audit Log system. The current system excludes bots and certain URLs via `AUDIT_LOG_EXCLUDE_BOTS` and `AUDIT_LOG_EXCLUDED_URLS` settings. This implementation will move these exclusion rules to the database for easier management.

## Implementation Requirements

### 1. User Agent Exclusion (LogUserAgent Model)

#### 1.1 Database Schema Changes

Add a boolean field to the `LogUserAgent` model:

```python
# Add to src/django_audit_log/models.py in LogUserAgent class
exclude_agent = models.BooleanField(
    default=False,
    help_text="Exclude this user agent from logging",
    verbose_name="Exclude Agent"
)
```

#### 1.2 Migration Required

Create a new migration file:

```python
# Generated migration file
class Migration(migrations.Migration):
    dependencies = [
        ("django_audit_log", "0004_alter_accesslog_user_agent_loguseragent_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="loguseragent",
            name="exclude_agent",
            field=models.BooleanField(
                default=False,
                help_text="Exclude this user agent from logging",
                verbose_name="Exclude Agent"
            ),
        ),
    ]
```

#### 1.3 Logic Changes

Update the `AccessLog.from_request()` method to check the database exclusion:

```python
# In AccessLog.from_request() method, replace bot exclusion logic:

# Current code (lines ~377-381):
# exclude_bots = getattr(settings, "AUDIT_LOG_EXCLUDE_BOTS", False)
# if exclude_bots and user_agent_obj and user_agent_obj.is_bot:
#     return None

# New code:
if user_agent_obj and user_agent_obj.exclude_agent:
    return None
```

#### 1.4 Admin Interface Changes

Update the `LogUserAgentAdmin` class in `admin.py`:

```python
# Add to LogUserAgentAdmin.list_display
list_display = (
    "browser",
    "browser_version",
    "operating_system",
    "operating_system_version",
    "device_type",
    "is_bot",
    "exclude_agent",  # Add this field
    "usage_count",
    "unique_users_count",
)

# Add to list_filter
list_filter = (
    "browser",
    "operating_system",
    "device_type",
    "is_bot",
    "exclude_agent",  # Add this filter
    "operating_system_version",
)

# Add to readonly_fields (remove exclude_agent to make it editable)
readonly_fields = (
    "user_agent",
    "browser",
    "browser_version",
    "operating_system",
    "operating_system_version",
    "device_type",
    "is_bot",
    "usage_details",
    "related_users",
    # Note: exclude_agent is NOT in readonly_fields to allow editing
)
```

#### 1.5 Admin Action Implementation

Add a custom admin action to delete all access log records for selected user agents:

```python
# Add to LogUserAgentAdmin class
@admin.action(description="Delete all access log records for selected user agents")
def delete_records_for_agents(self, request, queryset):
    """Delete all AccessLog records associated with the selected user agents."""
    from django.contrib import messages
    from django.db.models import Count

    # Count records to be deleted
    total_records = AccessLog.objects.filter(user_agent_normalized__in=queryset).count()

    if total_records == 0:
        messages.warning(request, "No access log records found for the selected user agents.")
        return

    # Delete the records
    deleted_count, _ = AccessLog.objects.filter(user_agent_normalized__in=queryset).delete()

    messages.success(
        request,
        f"Successfully deleted {deleted_count} access log records for {queryset.count()} user agent(s)."
    )

# Add to actions list
actions = ["delete_records_for_agents"]
```

### 2. URL Path Exclusion (LogPath Model)

#### 2.1 Database Schema Changes

Add a boolean field to the `LogPath` model:

```python
# Add to src/django_audit_log/models.py in LogPath class
exclude_path = models.BooleanField(
    default=False,
    help_text="Exclude this URL path from logging",
    verbose_name="Exclude This URL"
)
```

#### 2.2 Migration Required

```python
# Add to the same migration file
operations = [
    # ... existing operations ...
    migrations.AddField(
        model_name="logpath",
        name="exclude_path",
        field=models.BooleanField(
            default=False,
            help_text="Exclude this URL path from logging",
            verbose_name="Exclude This URL"
        ),
    ),
]
```

#### 2.3 Logic Changes

Update the `AccessLog.from_request()` and `AccessLog._check_sampling()` methods:

```python
# In AccessLog.from_request(), add path exclusion check:
# After creating the path object:
path_obj = LogPath.from_request(request)
if path_obj and path_obj.exclude_path:
    return None

# Update _check_sampling() method to check database exclusion:
path_obj = LogPath.objects.filter(path=path).first()
if path_obj and path_obj.exclude_path:
    return cls.SamplingResult(
        should_log=False,
        in_always_log_urls=False,
        in_sample_urls=False,
        sample_rate=getattr(settings, "AUDIT_LOG_SAMPLE_RATE", 1.0),
    )
```

#### 2.4 Admin Interface Changes

Update the `LogPathAdmin` class:

```python
# Update LogPathAdmin
class LogPathAdmin(ReadOnlyAdmin):
    list_display = ("path", "exclude_path", "access_count")
    search_fields = ("path",)
    list_filter = ("exclude_path",)
    readonly_fields = ("path", "access_count", "recent_activity")

    # Remove exclude_path from readonly_fields to make it editable
    def get_readonly_fields(self, request, obj=None):
        if obj:  # Editing existing object
            return ("path", "access_count", "recent_activity")
        return self.readonly_fields

    def access_count(self, obj):
        """Return the number of access log entries for this path."""
        return obj.accesslog_set.count()
    access_count.short_description = "Access Count"

    def recent_activity(self, obj):
        """Show recent activity for this path."""
        recent_logs = obj.accesslog_set.order_by('-timestamp')[:5]
        if not recent_logs:
            return "No recent activity"

        html = ["<ul>"]
        for log in recent_logs:
            html.append(f"<li>{log.timestamp} - {log.user} ({log.method})</li>")
        html.append("</ul>")
        return mark_safe("".join(html))
    recent_activity.short_description = "Recent Activity"
```

#### 2.5 Admin Action Implementation

```python
# Add to LogPathAdmin class
@admin.action(description="Delete all access log records for selected URL paths")
def delete_records_for_paths(self, request, queryset):
    """Delete all AccessLog records associated with the selected URL paths."""
    from django.contrib import messages

    # Count records to be deleted
    total_records = AccessLog.objects.filter(path__in=queryset).count()

    if total_records == 0:
        messages.warning(request, "No access log records found for the selected URL paths.")
        return

    # Delete the records
    deleted_count, _ = AccessLog.objects.filter(path__in=queryset).delete()

    messages.success(
        request,
        f"Successfully deleted {deleted_count} access log records for {queryset.count()} URL path(s)."
    )

# Add to actions list
actions = ["delete_records_for_paths"]
```

### 3. User Record Deletion (LogUser Model)

#### 3.1 Admin Action Implementation

Add a custom admin action to the existing `LogUserAdmin` class:

```python
# Add to LogUserAdmin.actions list (expand existing actions)
actions = ["clear_anonymous_logs", "delete_records_for_users"]

@admin.action(description="Delete all access log records for selected users")
def delete_records_for_users(self, request, queryset):
    """Delete all AccessLog records associated with the selected users."""
    from django.contrib import messages

    # Count records to be deleted
    total_records = AccessLog.objects.filter(user__in=queryset).count()

    if total_records == 0:
        messages.warning(request, "No access log records found for the selected users.")
        return

    # Delete the records
    deleted_count, _ = AccessLog.objects.filter(user__in=queryset).delete()

    messages.success(
        request,
        f"Successfully deleted {deleted_count} access log records for {queryset.count()} user(s)."
    )
```

## Implementation Steps

### Step 1: Database Migration

1. Create and run the migration to add the new boolean fields:
   ```bash
   python manage.py makemigrations django_audit_log
   python manage.py migrate
   ```

### Step 2: Update Models

1. Add the `exclude_agent` field to `LogUserAgent` model
2. Add the `exclude_path` field to `LogPath` model
3. Update the `__str__` methods if needed to display exclusion status

### Step 3: Update Business Logic

1. Modify `AccessLog.from_request()` method to check database exclusion flags
2. Update `AccessLog._check_sampling()` method for URL path exclusion
3. Ensure backward compatibility with existing settings-based exclusion

### Step 4: Update Admin Interface

1. Update `LogUserAgentAdmin` to include the new field and action
2. Update `LogPathAdmin` to include the new field and action
3. Add the deletion action to `LogUserAdmin`
4. Test all admin interfaces and actions

### Step 5: Data Migration (Optional)

Create a data migration to automatically mark existing bots and excluded URLs:

```python
# Data migration example
def migrate_existing_exclusions(apps, schema_editor):
    LogUserAgent = apps.get_model('django_audit_log', 'LogUserAgent')
    LogPath = apps.get_model('django_audit_log', 'LogPath')

    # Mark existing bots as excluded
    LogUserAgent.objects.filter(is_bot=True).update(exclude_agent=True)

    # Mark existing excluded URL patterns (if you can identify them)
    # This would require custom logic based on your current AUDIT_LOG_EXCLUDED_URLS
```

### Step 6: Testing

1. Test user agent exclusion functionality
2. Test URL path exclusion functionality
3. Test admin actions for record deletion
4. Verify that exclusion works as expected
5. Test with various user agent strings and URL patterns

## Backward Compatibility

To maintain backward compatibility during the transition:

```python
# In AccessLog.from_request(), check both settings and database
exclude_bots_setting = getattr(settings, "AUDIT_LOG_EXCLUDE_BOTS", False)
if user_agent_obj:
    # Check database exclusion first, then fall back to settings
    if user_agent_obj.exclude_agent or (exclude_bots_setting and user_agent_obj.is_bot):
        return None

# For URL exclusion, check database first, then settings
excluded_url_patterns = getattr(settings, "AUDIT_LOG_EXCLUDED_URLS", [])
path_obj = LogPath.objects.filter(path=request.path).first()
if path_obj and path_obj.exclude_path:
    return None

# Then check settings-based patterns
for pattern in excluded_url_patterns:
    if re.match(pattern, request.path):
        # ... existing logic
```

## Benefits

1. **Dynamic Configuration**: No need to restart the application to change exclusion rules
2. **Granular Control**: Ability to exclude specific user agents or URLs rather than patterns
3. **Admin Interface**: Easy management through Django admin
4. **Audit Trail**: Clear visibility of what is being excluded
5. **Bulk Operations**: Admin actions for bulk record deletion

## Security Considerations

1. Ensure proper permissions for admin users to modify exclusion settings
2. Log changes to exclusion settings for audit purposes
3. Consider adding confirmation dialogs for bulk deletion actions
4. Implement rate limiting for deletion operations if necessary

## Performance Considerations

1. Add database indexes on the new boolean fields for faster filtering
2. Consider caching frequently accessed exclusion rules
3. Monitor query performance after implementing database checks
4. Consider batch operations for large-scale exclusions

## File Changes Summary

- `src/django_audit_log/models.py`: Add exclusion fields, update logic
- `src/django_audit_log/admin.py`: Update admin classes and add actions
- `src/django_audit_log/migrations/`: New migration file
- Tests: Update existing tests and add new ones for exclusion functionality

This implementation provides a comprehensive solution for database-based exclusion management while maintaining backward compatibility and providing enhanced administrative capabilities.
