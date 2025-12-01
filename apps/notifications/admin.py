from django.contrib import admin

from .models import AuditLog, Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "level", "is_read", "created_at")
    list_filter = ("level", "is_read")
    search_fields = ("message", "user__username")
    ordering = ("-created_at",)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("id", "action", "entity_type", "entity_id", "timestamp", "user")
    list_filter = ("action", "entity_type")
    search_fields = ("entity_type", "entity_id", "user__username")
    ordering = ("-timestamp",)


