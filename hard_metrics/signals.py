from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.dispatch import receiver


def _ip(request):
    if request is None:
        return ""
    xf = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (xf.split(",")[0].strip() if xf else request.META.get("REMOTE_ADDR", ""))[:64]


@receiver(user_logged_in)
def _login(sender, request, user, **kw):
    from .models import AuditLog
    AuditLog.objects.create(user=user.get_username(), action="login", ip=_ip(request))


@receiver(user_login_failed)
def _failed(sender, credentials, request=None, **kw):
    from .models import AuditLog
    AuditLog.objects.create(user=str(credentials.get("username", ""))[:150], action="login_failed", ip=_ip(request), ok=False)
