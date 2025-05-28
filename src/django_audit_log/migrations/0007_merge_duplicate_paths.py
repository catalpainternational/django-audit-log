from collections import defaultdict
from urllib.parse import urlparse

from django.db import migrations


def normalize_path(url):
    """Normalize a URL by removing method, server, and port information."""
    if not url:
        return ""

    # Parse the URL
    parsed = urlparse(url)

    # If it's already just a path (no scheme/netloc), return it cleaned
    if not parsed.scheme and not parsed.netloc:
        return parsed.path

    # Return just the path component
    return parsed.path


def merge_duplicate_paths(apps, schema_editor):
    """
    Merge LogPath records that point to the same normalized path.
    Updates all foreign keys to point to the first instance of each path.
    """
    LogPath = apps.get_model("django_audit_log", "LogPath")
    AccessLog = apps.get_model("django_audit_log", "AccessLog")
    db_alias = schema_editor.connection.alias

    # Group paths by their normalized version
    path_groups = defaultdict(list)
    for path in LogPath.objects.using(db_alias).all():
        normalized = normalize_path(path.path)
        path_groups[normalized].append(path)

    # Process each group of paths
    for normalized_path, paths in path_groups.items():
        if len(paths) > 1:
            # Keep the first path instance and merge others into it
            primary_path = paths[0]
            duplicate_paths = paths[1:]

            # Update the primary path to use the normalized version
            primary_path.path = normalized_path
            primary_path.save()

            # Update all foreign keys to point to the primary path
            for duplicate in duplicate_paths:
                # Update AccessLog foreign keys
                AccessLog.objects.using(db_alias).filter(path=duplicate).update(
                    path=primary_path
                )

                AccessLog.objects.using(db_alias).filter(referrer=duplicate).update(
                    referrer=primary_path
                )

                AccessLog.objects.using(db_alias).filter(response_url=duplicate).update(
                    response_url=primary_path
                )

                # Delete the duplicate path
                duplicate.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("django_audit_log", "0006_loguseragent_operating_system_version"),
    ]

    operations = [
        migrations.RunPython(
            merge_duplicate_paths,
            # No reverse migration provided as this is a data cleanup
            reverse_code=migrations.RunPython.noop,
        ),
    ]
