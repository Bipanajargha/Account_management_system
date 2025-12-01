from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.accounts.models import LedgerAccount


class Transaction(models.Model):
    TYPE_INCOMING = "incoming"
    TYPE_OUTGOING = "outgoing"
    TYPE_CHOICES = [
        (TYPE_INCOMING, "Incoming"),
        (TYPE_OUTGOING, "Outgoing"),
    ]

    METHOD_CASH = "cash"
    METHOD_BANK = "bank"
    METHOD_ONLINE = "online"
    METHOD_CHOICES = [
        (METHOD_CASH, "Cash"),
        (METHOD_BANK, "Bank"),
        (METHOD_ONLINE, "Online"),
    ]

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    id = models.BigAutoField(primary_key=True)
    ledger = models.ForeignKey(LedgerAccount, on_delete=models.CASCADE, related_name="transactions")
    transaction_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    payment_method = models.CharField(max_length=20, choices=METHOD_CHOICES)
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    currency = models.CharField(max_length=10, default="USD")
    description = models.TextField(blank=True)
    reference = models.CharField(max_length=64, blank=True)
    transaction_date = models.DateField(default=timezone.now)
    status = models.CharField(max_length=20, default=STATUS_PENDING)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="transactions",
    )
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="approved_transactions",
    )
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-transaction_date", "-id"]

    def __str__(self) -> str:
        return f"{self.transaction_type} {self.amount} ({self.payment_method})"

    def mark_approved(self, user):
        self.status = self.STATUS_APPROVED
        self.approved_by = user
        self.approved_at = timezone.now()
        self.save(update_fields=["status", "approved_by", "approved_at"])


class Voucher(models.Model):
    TYPE_PAYMENT = "payment"
    TYPE_RECEIPT = "receipt"
    TYPE_JOURNAL = "journal"

    id = models.BigAutoField(primary_key=True)
    transaction = models.OneToOneField(Transaction, on_delete=models.CASCADE, related_name="voucher")
    voucher_type = models.CharField(
        max_length=20,
        choices=[
            (TYPE_PAYMENT, "Payment"),
            (TYPE_RECEIPT, "Receipt"),
            (TYPE_JOURNAL, "Journal"),
        ],
    )
    issued_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"{self.voucher_type} voucher for transaction {self.transaction_id}"


class Receipt(models.Model):
    id = models.BigAutoField(primary_key=True)
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name="receipts")
    issued_to = models.CharField(max_length=120)
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    issued_at = models.DateTimeField(auto_now_add=True)
    payment_method = models.CharField(max_length=20, choices=Transaction.METHOD_CHOICES)
    details = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"Receipt {self.id}"


