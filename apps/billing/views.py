from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from ams.permissions import (
    ROLE_ACCOUNTANT,
    ROLE_ADMIN,
    ROLE_MANAGER,
    RoleBasedPermission,
)
from apps.notifications.models import Notification
from apps.notifications.utils import create_notification, log_audit

from .models import Bill, Invoice, PaymentRecord
from .serializers import BillSerializer, InvoiceSerializer, PaymentRecordSerializer


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.select_related("customer", "ledger").all()
    serializer_class = InvoiceSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filterset_fields = ["status", "customer", "ledger"]
    search_fields = ["number", "description"]

    def perform_create(self, serializer):
        invoice = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="invoice",
            entity_id=str(invoice.pk),
            metadata={"number": invoice.number},
        )

    @action(detail=True, methods=["post"])
    def send_reminder(self, request, pk=None):
        invoice = self.get_object()
        create_notification(
            message=f"Invoice {invoice.number} is due on {invoice.due_date}",
            user=invoice.customer,
            level=Notification.LEVEL_WARNING,
        )
        from django.utils import timezone

        invoice.last_reminder_sent = timezone.now()
        invoice.save(update_fields=["last_reminder_sent"])
        return Response({"detail": "Reminder queued."})


class BillViewSet(viewsets.ModelViewSet):
    queryset = Bill.objects.select_related("ledger").all()
    serializer_class = BillSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filterset_fields = ["status", "payment_method", "ledger"]
    search_fields = ["reference", "vendor_name"]

    def perform_create(self, serializer):
        bill = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="bill",
            entity_id=str(bill.pk),
        )

    @action(detail=True, methods=["post"])
    def mark_overdue(self, request, pk=None):
        bill = self.get_object()
        bill.status = Invoice.STATUS_OVERDUE
        bill.save(update_fields=["status"])
        create_notification(
            message=f"Bill {bill.reference} is overdue.",
            level=Notification.LEVEL_WARNING,
        )
        return Response({"detail": "Bill marked as overdue."})


class PaymentRecordViewSet(viewsets.ModelViewSet):
    queryset = PaymentRecord.objects.select_related("invoice", "bill").all()
    serializer_class = PaymentRecordSerializer
    permission_classes = [RoleBasedPermission]
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    filterset_fields = ["method", "invoice", "bill"]
    search_fields = ["reference"]

    def perform_create(self, serializer):
        payment = serializer.save()
        log_audit(
            user=self.request.user,
            action="create",
            entity_type="payment_record",
            entity_id=str(payment.pk),
            metadata={"amount": str(payment.amount)},
        )
