from django.http.request import HttpRequest
from django.http.response import HttpResponse

from .models import AccessLog


class AuditLogMiddleware:
    """
    This is a middleware which is intended to log some / all requests
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        AccessLog.from_request(request, response)
        return response
