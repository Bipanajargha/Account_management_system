from __future__ import annotations

from typing import Any, Optional

from django.db import transaction

from .models import AuditLog, Notification


def create_notification(
    *,
    message: str,
    level: str = Notification.LEVEL_INFO,
    user_id: Optional[int] = None,
) -> Notification:
    """
    Helper to create notifications safely.
    """

    with transaction.atomic():
        notification = Notification.objects.create(
            user_id=user_id,
            message=message,
            level=level,
        )
    return notification


def log_audit(
    *,
    user_id: Optional[int],
    action: str,
    entity_type: str,
    entity_id: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """
    Helper to write audit logs consistently.
    """

    with transaction.atomic():
        audit = AuditLog.objects.create(
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id or "",
            metadata=metadata or {},
        )
    return audit


class AuditLogMixin:
    """
    ViewSet mixin to automatically create audit records.
    """

    audit_entity = ""

    def _audit_entity(self, instance) -> str:
        if self.audit_entity:
            return self.audit_entity
        return instance.__class__.__name__

    def _request_user_pk(self):
        request = getattr(self, "request", None)
        if request and getattr(request, "user", None):
            return getattr(request.user, "pk", None)
        return None

    def audit_create(self, instance):
        log_audit(
            user_id=self._request_user_pk(),
            action=AuditLog.ACTION_CREATE,
            entity_type=self._audit_entity(instance),
            entity_id=str(getattr(instance, "pk", "")),
        )

    def audit_update(self, instance):
        log_audit(
            user_id=self._request_user_pk(),
            action=AuditLog.ACTION_UPDATE,
            entity_type=self._audit_entity(instance),
            entity_id=str(getattr(instance, "pk", "")),
        )

    def audit_delete(self, instance):
        log_audit(
            user_id=self._request_user_pk(),
            action=AuditLog.ACTION_DELETE,
            entity_type=self._audit_entity(instance),
            entity_id=str(getattr(instance, "pk", "")),
        )

    def perform_create(self, serializer):
        instance = serializer.save()
        self.audit_create(instance)
        return instance

    def perform_update(self, serializer):
        instance = serializer.save()
        self.audit_update(instance)
        return instance

    def perform_destroy(self, instance):
        self.audit_delete(instance)
        return super().perform_destroy(instance)


