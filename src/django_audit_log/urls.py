"""URLs for Django Audit Log admin actions."""

from django.urls import path
from . import views

app_name = 'django_audit_log'

urlpatterns = [
    # Individual delete operations
    path('delete-user-logs/<int:user_id>/', views.delete_user_logs, name='delete_user_logs'),
    path('delete-path-logs/<int:path_id>/', views.delete_path_logs, name='delete_path_logs'),
    path('delete-ip-logs/<int:ip_id>/', views.delete_ip_logs, name='delete_ip_logs'),
    path('delete-user-agent-logs/<int:user_agent_id>/', views.delete_user_agent_logs, name='delete_user_agent_logs'),
    
    # Toggle exclusions
    path('toggle-path-exclusion/<int:path_id>/', views.toggle_path_exclusion, name='toggle_path_exclusion'),
    path('toggle-user-agent-exclusion/<int:user_agent_id>/', views.toggle_user_agent_exclusion, name='toggle_user_agent_exclusion'),
    
    # Bulk delete operations
    path('bulk-delete-user-logs/', views.bulk_delete_user_logs, name='bulk_delete_user_logs'),
    path('bulk-delete-path-logs/', views.bulk_delete_path_logs, name='bulk_delete_path_logs'),
    path('bulk-delete-user-agent-logs/', views.bulk_delete_user_agent_logs, name='bulk_delete_user_agent_logs'),
    
    # Special operations
    path('clear-anonymous-logs/', views.clear_anonymous_logs, name='clear_anonymous_logs'),
] 