from django.contrib import admin

from .models import IncomeStatement


@admin.register(IncomeStatement)
class IncomeStatementAdmin(admin.ModelAdmin):
    list_display = ["report", "total_revenue", "total_expense", "net_income"]
    search_fields = ["report__id"]