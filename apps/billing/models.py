from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.accounts.models import LedgerAccount


class Invoice(models.Model):
    STATUS_DRAFT = "draft"
    STATUS_SENT = "sent"
    STATUS_PAID = "paid"
    STATUS_OVERDUE = "overdue"
    STATUS_CANCELLED = "cancelled"

    STATUS_CHOICES = [
        (STATUS_DRAFT, "Draft"),
        (STATUS_SENT, "Sent"),
        (STATUS_PAID, "Paid"),
        (STATUS_OVERDUE, "Overdue"),
        (STATUS_CANCELLED, "Cancelled"),
    ]

    id = models.BigAutoField(primary_key=True)
    number = models.CharField(max_length=32, unique=True)
    customer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="invoices",
    )
    ledger = models.ForeignKey(
        LedgerAccount,
        on_delete=models.CASCADE,
        related_name="invoices",
    )
    description = models.TextField(blank=True)
    issue_date = models.DateField(default=timezone.now)
    due_date = models.DateField()
    subtotal = models.DecimalField(max_digits=14, decimal_places=2)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    discount_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    notes = models.TextField(blank=True)
    last_reminder_sent = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-issue_date", "-id"]

    def __str__(self) -> str:
        return f"Invoice {self.number}"

    @property
    def tax_amount(self):
        return (self.subtotal * self.tax_rate) / 100

    @property
    def discount_amount(self):
        return (self.subtotal * self.discount_rate) / 100

    @property
    def total_due(self):
        return self.subtotal + self.tax_amount - self.discount_amount

    @property
    def is_overdue(self):
        return self.status not in {self.STATUS_PAID, self.STATUS_CANCELLED} and self.due_date < timezone.now().date()


class Bill(models.Model):
    TYPE_VENDOR = "vendor"
    TYPE_SUPPLIER = "supplier"

    id = models.BigAutoField(primary_key=True)
    reference = models.CharField(max_length=32, unique=True)
    vendor_name = models.CharField(max_length=120)
    ledger = models.ForeignKey(LedgerAccount, on_delete=models.CASCADE, related_name="bills")
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    discount_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    issued_date = models.DateField(default=timezone.now)
    due_date = models.DateField()
    status = models.CharField(
        max_length=20,
        choices=Invoice.STATUS_CHOICES,
        default=Invoice.STATUS_DRAFT,
    )
    payment_method = models.CharField(
        max_length=20,
        choices=[
            ("cash", "Cash"),
            ("bank", "Bank"),
            ("online", "Online"),
        ],
        default="bank",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-issued_date"]

    def __str__(self) -> str:
        return f"Bill {self.reference}"

    @property
    def total_due(self):
        tax = (self.amount * self.tax_rate) / 100
        discount = (self.amount * self.discount_rate) / 100
        return self.amount + tax - discount

    @property
    def is_overdue(self):
        return self.status not in {Invoice.STATUS_PAID, Invoice.STATUS_CANCELLED} and self.due_date < timezone.now().date()


class PaymentRecord(models.Model):
    METHOD_CASH = "cash"
    METHOD_BANK = "bank"
    METHOD_ONLINE = "online"
    METHOD_CHOICES = [
        (METHOD_CASH, "Cash"),
        (METHOD_BANK, "Bank"),
        (METHOD_ONLINE, "Online"),
    ]

    id = models.BigAutoField(primary_key=True)
    invoice = models.ForeignKey(
        Invoice,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="payments",
    )
    bill = models.ForeignKey(
        Bill,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="payments",
    )
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    method = models.CharField(max_length=20, choices=METHOD_CHOICES)
    payment_date = models.DateField(default=timezone.now)
    reference = models.CharField(max_length=64, blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="billing_payments",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-payment_date", "-id"]

    def __str__(self) -> str:
        target = self.invoice.number if self.invoice else self.bill.reference if self.bill else "N/A"
        return f"Payment {self.id} for {target}"

    def clean(self):
        if not self.invoice and not self.bill:
            raise ValidationError("A payment must reference an invoice or a bill.")

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)
        if self.invoice:
            self.invoice.status = Invoice.STATUS_PAID if self.invoice.total_due <= self._total_invoice_payments() else Invoice.STATUS_SENT
            self.invoice.save(update_fields=["status"])
        if self.bill:
            self.bill.status = Invoice.STATUS_PAID if self.bill.total_due <= self._total_bill_payments() else self.bill.status
            self.bill.save(update_fields=["status"])

    def _total_invoice_payments(self):
        return (
            self.invoice.payments.aggregate(total=models.Sum("amount"))["total"]
            or 0
        )

    def _total_bill_payments(self):
        return (
            self.bill.payments.aggregate(total=models.Sum("amount"))["total"]
            or 0
        )