# Generated by Django 5.1.7 on 2025-04-02 07:04

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_audit_log", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="accesslog",
            name="user_agent",
            field=models.TextField(
                blank=True, help_text="User Agent string", null=True
            ),
        ),
    ]
