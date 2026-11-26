from django.db import models


class AuditLog(models.Model):
    ts = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.CharField(max_length=150)
    action = models.CharField(max_length=40)
    target = models.CharField(max_length=500, blank=True)
    ip = models.CharField(max_length=64, blank=True)
    ok = models.BooleanField(default=True)
    detail = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-ts"]
