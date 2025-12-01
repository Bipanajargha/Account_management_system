from rest_framework import serializers

from .models import AuditLog, Notification


class NotificationSerializer(serializers.ModelSerializer):
    user_display = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Notification
        fields = [
            "id",
            "user",
            "user_display",
            "message",
            "level",
            "is_read",
            "created_at",
        ]
        read_only_fields = ["id", "created_at", "user_display"]


class AuditLogSerializer(serializers.ModelSerializer):
    user_display = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "user",
            "user_display",
            "action",
            "entity_type",
            "entity_id",
            "timestamp",
            "metadata",
        ]
        read_only_fields = ["id", "timestamp", "user_display"]

