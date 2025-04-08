from .models import AccessLog


class AccessLogMixin:
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        AccessLog.from_request(request, response)
        return response
