"""Views for Django Audit Log admin actions."""

from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import permission_required
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.http import HttpResponseForbidden
from django.urls import reverse

from .models import LogUser, LogPath, LogIpAddress, LogUserAgent, AccessLog


def _check_delete_permission(user):
    """Check if user has permission to delete access logs."""
    return user.is_superuser or user.has_perm('django_audit_log.delete_accesslog')


@staff_member_required
@require_http_methods(["POST"])
def delete_user_logs(request, user_id):
    """Delete all access logs for a specific user."""
    if not _check_delete_permission(request.user):
        return HttpResponseForbidden("You don't have permission to delete access logs.")
    
    user = get_object_or_404(LogUser, id=user_id)
    
    try:
        with transaction.atomic():
            count, _ = AccessLog.objects.filter(user=user).delete()
            
            if count > 0:
                messages.success(
                    request,
                    f'Successfully deleted {count} access log records for user "{user.user_name}".'
                )
            else:
                messages.warning(
                    request,
                    f'No access log records found for user "{user.user_name}".'
                )
                
    except Exception as e:
        messages.error(
            request,
            f'Error deleting access log records for user "{user.user_name}": {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_loguser_change', user_id)


@staff_member_required
@require_http_methods(["POST"])
def delete_path_logs(request, path_id):
    """Delete all access logs for a specific path."""
    if not _check_delete_permission(request.user):
        return HttpResponseForbidden("You don't have permission to delete access logs.")
    
    path = get_object_or_404(LogPath, id=path_id)
    
    try:
        with transaction.atomic():
            count, _ = AccessLog.objects.filter(path=path).delete()
            
            if count > 0:
                messages.success(
                    request,
                    f'Successfully deleted {count} access log records for path "{path.path}".'
                )
            else:
                messages.warning(
                    request,
                    f'No access log records found for path "{path.path}".'
                )
                
    except Exception as e:
        messages.error(
            request,
            f'Error deleting access log records for path "{path.path}": {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_logpath_change', path_id)


@staff_member_required
@require_http_methods(["POST"])
def delete_ip_logs(request, ip_id):
    """Delete all access logs for a specific IP address."""
    if not _check_delete_permission(request.user):
        return HttpResponseForbidden("You don't have permission to delete access logs.")
    
    ip = get_object_or_404(LogIpAddress, id=ip_id)
    
    try:
        with transaction.atomic():
            count, _ = AccessLog.objects.filter(ip=ip).delete()
            
            if count > 0:
                messages.success(
                    request,
                    f'Successfully deleted {count} access log records for IP "{ip.address}".'
                )
            else:
                messages.warning(
                    request,
                    f'No access log records found for IP "{ip.address}".'
                )
                
    except Exception as e:
        messages.error(
            request,
            f'Error deleting access log records for IP "{ip.address}": {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_logipaddress_change', ip_id)


@staff_member_required
@require_http_methods(["POST"])
def delete_user_agent_logs(request, user_agent_id):
    """Delete all access logs for a specific user agent."""
    if not _check_delete_permission(request.user):
        return HttpResponseForbidden("You don't have permission to delete access logs.")
    
    user_agent = get_object_or_404(LogUserAgent, id=user_agent_id)
    
    try:
        with transaction.atomic():
            count, _ = AccessLog.objects.filter(user_agent_normalized=user_agent).delete()
            
            if count > 0:
                messages.success(
                    request,
                    f'Successfully deleted {count} access log records for user agent "{user_agent.browser} {user_agent.browser_version}".'
                )
            else:
                messages.warning(
                    request,
                    f'No access log records found for user agent "{user_agent.browser} {user_agent.browser_version}".'
                )
                
    except Exception as e:
        messages.error(
            request,
            f'Error deleting access log records for user agent: {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_loguseragent_change', user_agent_id)


@staff_member_required
@require_http_methods(["POST"])
def toggle_path_exclusion(request, path_id):
    """Toggle exclusion status for a specific path."""
    if not (request.user.is_superuser or request.user.has_perm('django_audit_log.change_logpath')):
        return HttpResponseForbidden("You don't have permission to modify path exclusions.")
    
    path = get_object_or_404(LogPath, id=path_id)
    
    try:
        with transaction.atomic():
            path.exclude_path = not path.exclude_path
            path.save()
            
            status = "excluded from" if path.exclude_path else "included in"
            messages.success(
                request,
                f'Path "{path.path}" is now {status} logging.'
            )
                
    except Exception as e:
        messages.error(
            request,
            f'Error updating exclusion status for path "{path.path}": {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_logpath_change', path_id)


@staff_member_required
@require_http_methods(["POST"])
def toggle_user_agent_exclusion(request, user_agent_id):
    """Toggle exclusion status for a specific user agent."""
    if not (request.user.is_superuser or request.user.has_perm('django_audit_log.change_loguseragent')):
        return HttpResponseForbidden("You don't have permission to modify user agent exclusions.")
    
    user_agent = get_object_or_404(LogUserAgent, id=user_agent_id)
    
    try:
        with transaction.atomic():
            user_agent.exclude_agent = not user_agent.exclude_agent
            user_agent.save()
            
            status = "excluded from" if user_agent.exclude_agent else "included in"
            messages.success(
                request,
                f'User agent "{user_agent.browser} {user_agent.browser_version}" is now {status} logging.'
            )
                
    except Exception as e:
        messages.error(
            request,
            f'Error updating exclusion status for user agent: {str(e)}'
        )
    
    # Redirect back to the admin change page or changelist
    if 'next' in request.POST:
        return redirect(request.POST['next'])
    return redirect('admin:django_audit_log_loguseragent_change', user_agent_id) 