from django.conf import settings
from django.db import models


class Notification(models.Model):
    """
    Stores system notifications such as due payments, low balances,
    unpaid invoices, and major updates for admins.
    """

    LEVEL_INFO = "info"
    LEVEL_WARNING = "warning"
    LEVEL_CRITICAL = "critical"

    LEVEL_CHOICES = [
        (LEVEL_INFO, "Info"),
        (LEVEL_WARNING, "Warning"),
        (LEVEL_CRITICAL, "Critical"),
    ]

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    message = models.TextField()
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default=LEVEL_INFO)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.level.upper()}: {self.message[:50]}"


class AuditLog(models.Model):
    """
    Generic audit log for user and transaction activity.
    """

    ACTION_CREATE = "create"
    ACTION_UPDATE = "update"
    ACTION_DELETE = "delete"
    ACTION_LOGIN = "login"

    ACTION_CHOICES = [
        (ACTION_CREATE, "Create"),
        (ACTION_UPDATE, "Update"),
        (ACTION_DELETE, "Delete"),
        (ACTION_LOGIN, "Login"),
    ]

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    entity_type = models.CharField(max_length=100)
    entity_id = models.CharField(max_length=100, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self) -> str:
        return f"{self.action} {self.entity_type} ({self.entity_id})"


