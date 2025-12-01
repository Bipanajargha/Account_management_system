from django.conf import settings
from django.db import models


class Report(models.Model):
    TYPE_INCOME = "income"
    TYPE_EXPENSE = "expense"
    TYPE_PROFIT_LOSS = "profit_loss"
    TYPE_BALANCE_SHEET = "balance_sheet"

    TYPE_CHOICES = [
        (TYPE_INCOME, "Income"),
        (TYPE_EXPENSE, "Expense"),
        (TYPE_PROFIT_LOSS, "Profit & Loss"),
        (TYPE_BALANCE_SHEET, "Balance Sheet"),
    ]

    FORMAT_PDF = "pdf"
    FORMAT_EXCEL = "excel"
    FORMAT_CSV = "csv"

    FORMAT_CHOICES = [
        (FORMAT_PDF, "PDF"),
        (FORMAT_EXCEL, "Excel"),
        (FORMAT_CSV, "CSV"),
    ]

    id = models.BigAutoField(primary_key=True)
    report_type = models.CharField(max_length=32, choices=TYPE_CHOICES)
    start_date = models.DateField()
    end_date = models.DateField()
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="requested_reports",
    )
    generated_at = models.DateTimeField(auto_now_add=True)
    export_format = models.CharField(
        max_length=16,
        choices=FORMAT_CHOICES,
        default=FORMAT_PDF,
    )
    data = models.JSONField(default=dict)
    filters = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, default="generated")

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"{self.get_report_type_display()} ({self.start_date} - {self.end_date})"


