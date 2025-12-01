from django.db import models
from apps.reports.models import Report

class IncomeStatement(models.Model):
    ISID = models.CharField(max_length=50, primary_key=True)
    ReportID = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='income_statements')
    TotalRevenue = models.DecimalField(max_digits=15, decimal_places=2)
    TotalExpense = models.DecimalField(max_digits=15, decimal_places=2)
    NetIncome = models.DecimalField(max_digits=15, decimal_places=2)

    def __str__(self):
        return f"Income Statement {self.ISID}"
    #bishal added