from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, mixins, viewsets

from ams.permissions import (
    ROLE_ACCOUNTANT,
    ROLE_ADMIN,
    ROLE_MANAGER,
    RoleBasedPermission,
)
from apps.notifications.utils import log_audit

from .models import AccountBalance, AccountCategory, LedgerAccount, LedgerEntry
from .serializers import (
    AccountBalanceSerializer,
    AccountCategorySerializer,
    LedgerAccountSerializer,
    LedgerEntrySerializer,
)

class AccountCategoryViewSet(viewsets.ModelViewSet):
    queryset = AccountCategory.objects.all().order_by("name")
    serializer_class = AccountCategorySerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["name", "code"]
    ordering_fields = ["name", "code", "created_at"]

    def perform_create(self, serializer):
        category = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="account_category",
            entity_id=str(category.pk),
        )


class LedgerAccountViewSet(viewsets.ModelViewSet):
    queryset = LedgerAccount.objects.select_related("category", "owner", "balance").all()
    serializer_class = LedgerAccountSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["category", "is_active"]
    search_fields = ["name", "code", "description"]
    ordering_fields = ["code", "name", "created_at"]

    def perform_create(self, serializer):
        ledger = serializer.save(owner=self.request.user)
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="ledger_account",
            entity_id=str(ledger.pk),
        )


class LedgerEntryViewSet(viewsets.ModelViewSet):
    queryset = LedgerEntry.objects.select_related("ledger", "ledger__category", "created_by").all()
    serializer_class = LedgerEntrySerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["ledger", "entry_type", "payment_method", "entry_date"]
    search_fields = ["reference", "description"]
    ordering_fields = ["entry_date", "amount", "created_at"]
    ordering = ["-entry_date"]

    def perform_create(self, serializer):
        entry = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="ledger_entry",
            entity_id=str(entry.pk),
            metadata={"amount": str(entry.amount)},
        )


class AccountBalanceViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    queryset = AccountBalance.objects.select_related("ledger").all()
    serializer_class = AccountBalanceSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
