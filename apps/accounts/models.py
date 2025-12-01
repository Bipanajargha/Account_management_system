from django.conf import settings
from django.db import models
from django.db.models import Sum
from django.utils import timezone


class AccountCategory(models.Model):
    TYPE_ASSET = "asset"
    TYPE_LIABILITY = "liability"
    TYPE_INCOME = "income"
    TYPE_EXPENSE = "expense"

    TYPE_CHOICES = [
        (TYPE_ASSET, "Asset"),
        (TYPE_LIABILITY, "Liability"),
        (TYPE_INCOME, "Income"),
        (TYPE_EXPENSE, "Expense"),
    ]

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=120, unique=True)
    code = models.CharField(max_length=32, unique=True)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Account Categories"

    def __str__(self) -> str:
        return f"{self.code} - {self.name}"


class LedgerAccount(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=120)
    code = models.CharField(max_length=32, unique=True)
    category = models.ForeignKey(AccountCategory, on_delete=models.CASCADE, related_name="ledgers")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="ledger_accounts",
    )
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["code"]

    def __str__(self) -> str:
        return f"{self.code} - {self.name}"

    def recalculate_balance(self):
        debit_total = self.entries.filter(entry_type=LedgerEntry.TYPE_DEBIT).aggregate(
            total=Sum("amount")
        )["total"] or 0
        credit_total = self.entries.filter(entry_type=LedgerEntry.TYPE_CREDIT).aggregate(
            total=Sum("amount")
        )["total"] or 0
        balance_value = debit_total - credit_total
        balance, _ = AccountBalance.objects.get_or_create(ledger=self)
        balance.balance = balance_value
        balance.updated_at = timezone.now()
        balance.save()


class LedgerEntry(models.Model):
    TYPE_DEBIT = "debit"
    TYPE_CREDIT = "credit"
    TYPE_CHOICES = [
        (TYPE_DEBIT, "Debit"),
        (TYPE_CREDIT, "Credit"),
    ]

    PAYMENT_CASH = "cash"
    PAYMENT_BANK = "bank"
    PAYMENT_ONLINE = "online"
    PAYMENT_CHOICES = [
        (PAYMENT_CASH, "Cash"),
        (PAYMENT_BANK, "Bank"),
        (PAYMENT_ONLINE, "Online"),
    ]

    id = models.BigAutoField(primary_key=True)
    ledger = models.ForeignKey(LedgerAccount, on_delete=models.CASCADE, related_name="entries")
    entry_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    amount = models.DecimalField(max_digits=14, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=PAYMENT_CHOICES)
    description = models.TextField(blank=True)
    reference = models.CharField(max_length=64, blank=True)
    entry_date = models.DateField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="ledger_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-entry_date", "-id"]

    def __str__(self) -> str:
        return f"{self.entry_type} {self.amount} on {self.entry_date}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.ledger.recalculate_balance()

    def delete(self, *args, **kwargs):
        ledger = self.ledger
        super().delete(*args, **kwargs)
        ledger.recalculate_balance()


class AccountBalance(models.Model):
    ledger = models.OneToOneField(LedgerAccount, on_delete=models.CASCADE, related_name="balance")
    balance = models.DecimalField(max_digits=14, decimal_places=2, default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.ledger.code}: {self.balance}"

