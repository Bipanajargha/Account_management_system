from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from ams.permissions import (
    ROLE_ACCOUNTANT,
    ROLE_ADMIN,
    ROLE_MANAGER,
    RoleBasedPermission,
)
from apps.notifications.utils import log_audit

from .models import Receipt, Transaction, Voucher
from .serializers import ReceiptSerializer, TransactionSerializer, VoucherSerializer


class TransactionViewSet(viewsets.ModelViewSet):
    queryset = Transaction.objects.select_related("ledger", "created_by").all()
    serializer_class = TransactionSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    action_allowed_roles = {"approve": [ROLE_ADMIN, ROLE_MANAGER]}
    filterset_fields = ["transaction_type", "payment_method", "status", "ledger"]
    search_fields = ["description", "reference"]

    def perform_create(self, serializer):
        transaction = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="transaction",
            entity_id=str(transaction.pk),
            metadata={"amount": str(transaction.amount)},
        )

    @action(detail=True, methods=["post"], permission_classes=[RoleBasedPermission])
    def approve(self, request, pk=None):
        transaction = self.get_object()
        if not request.user.has_role(ROLE_ADMIN, ROLE_MANAGER):
            return Response(
                {"detail": "Only admins or managers can approve transactions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        transaction.mark_approved(request.user)
        log_audit(
            user=request.user,
            action="update",
            entity_type="transaction",
            entity_id=str(transaction.pk),
            metadata={"status": transaction.status},
        )
        return Response({"detail": "Transaction approved."})


class VoucherViewSet(viewsets.ModelViewSet):
    queryset = Voucher.objects.select_related("transaction").all()
    serializer_class = VoucherSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]


class ReceiptViewSet(viewsets.ModelViewSet):
    queryset = Receipt.objects.select_related("transaction").all()
    serializer_class = ReceiptSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
