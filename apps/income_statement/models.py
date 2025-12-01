from django.db import models

from apps.reports.models import Report


class IncomeStatement(models.Model):
    report = models.OneToOneField(
        Report,
        on_delete=models.CASCADE,
        related_name="income_statement",
    )
    total_revenue = models.DecimalField(max_digits=15, decimal_places=2)
    total_expense = models.DecimalField(max_digits=15, decimal_places=2)
    net_income = models.DecimalField(max_digits=15, decimal_places=2)

    def __str__(self):
        return f"Income Statement for report {self.report_id}"