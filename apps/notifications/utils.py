from typing import Any, Dict, Iterable, Optional

from django.contrib.auth import get_user_model

from .models import AuditLog, Notification

User = get_user_model()


def log_audit(
    *,
    user: Optional[User] = None,
    action: str,
    entity_type: str,
    entity_id: Optional[str] = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Helper for writing audit log entries in a consistent format.
    """

    return AuditLog.objects.create(
        user=user,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id or ""),
        metadata=metadata or {},
    )


def create_notification(
    *,
    message: str,
    level: str = Notification.LEVEL_INFO,
    user: Optional[User] = None,
    user_id: Optional[int] = None,
) -> Notification:
    """
    Create a single notification for a user or broadcast to admins/managers.
    """

    target_user = user
    if user_id and target_user is None:
        target_user = User.objects.filter(pk=user_id).first()

    if target_user:
        return Notification.objects.create(user=target_user, message=message, level=level)
    return notify_users(message=message, level=level)


def notify_users(
    *,
    message: str,
    users: Optional[Iterable[User]] = None,
    level: str = Notification.LEVEL_INFO,
) -> Notification:
    """
    Helper to fan out notifications to one or many users. Returns the last notification created for convenience.
    """

    recipients = list(users) if users is not None else User.objects.filter(
        Permissions__in=[User.ROLE_ADMIN, User.ROLE_MANAGER]
    )
    notifications = Notification.objects.bulk_create(
        [
            Notification(user=user, message=message, level=level)
            for user in recipients
        ]
    )
    return notifications[-1] if notifications else Notification.objects.create(
        user=None,
        message=message,
        level=level,
    )


# Backwards compatible alias
notify = create_notification

