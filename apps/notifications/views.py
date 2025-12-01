from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, mixins, permissions, viewsets
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework.response import Response

from ams.permissions import ROLE_ACCOUNTANT, ROLE_ADMIN, ROLE_CUSTOMER, ROLE_MANAGER, RoleBasedPermission
from .models import AuditLog, Notification
from .serializers import AuditLogSerializer, NotificationSerializer


class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER, ROLE_CUSTOMER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ["level", "is_read"]
    search_fields = ["message"]
    ordering = ["-created_at"]

    def get_permissions(self):
        if self.action in {"mark_all_read", "partial_update", "update"}:
            return [permissions.IsAuthenticated()]
        if self.action == "destroy":
            return [permissions.IsAuthenticated()]
        return super().get_permissions()

    def get_queryset(self):
        # When generating Swagger schema, drf-yasg creates a fake view with no real user.
        if getattr(self, "swagger_fake_view", False):
            return Notification.objects.none()

        user = self.request.user
        # Anonymous users should not hit the DB with an AnonymousUser FK
        if not user.is_authenticated:
            return Notification.objects.none()

        if hasattr(user, "has_role") and user.has_role(ROLE_ADMIN, ROLE_MANAGER):
            return Notification.objects.all().order_by("-created_at")
        return Notification.objects.filter(user=user).order_by("-created_at")

    def perform_update(self, serializer):
        instance = serializer.instance
        if instance.user_id != self.request.user.pk and not self.request.user.has_role(
            ROLE_ADMIN, ROLE_MANAGER
        ):
            raise PermissionDenied("You can only update your own notifications.")
        serializer.save()

    def perform_destroy(self, instance):
        if not self.request.user.has_role(ROLE_ADMIN, ROLE_MANAGER):
            raise PermissionDenied("Only admins/managers can delete notifications.")
        return super().perform_destroy(instance)

    @action(detail=False, methods=["post"])
    def mark_all_read(self, request):
        queryset = self.get_queryset()
        updated = queryset.update(is_read=True)
        return Response({"updated": updated})


class AuditLogViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    queryset = AuditLog.objects.select_related("user").all()
    serializer_class = AuditLogSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["entity_type", "entity_id", "action"]
    ordering_fields = ["timestamp", "action", "entity_type"]
    ordering = ["-timestamp"]


