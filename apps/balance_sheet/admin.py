from django.contrib import admin

from .models import BalanceSheet


@admin.register(BalanceSheet)
class BalanceSheetAdmin(admin.ModelAdmin):
    list_display = ["report", "total_assets", "total_liabilities", "total_equity"]
    search_fields = ["report__id"]