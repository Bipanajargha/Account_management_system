from django.db import models

from apps.reports.models import Report


class BalanceSheet(models.Model):
    report = models.OneToOneField(
        Report,
        on_delete=models.CASCADE,
        related_name="balance_sheet",
    )
    total_liabilities = models.DecimalField(max_digits=15, decimal_places=2)
    total_assets = models.DecimalField(max_digits=15, decimal_places=2)
    total_equity = models.DecimalField(max_digits=15, decimal_places=2)

    def __str__(self):
        return f"Balance Sheet for report {self.report_id}"