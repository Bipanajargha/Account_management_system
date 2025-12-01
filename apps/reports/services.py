from __future__ import annotations

from decimal import Decimal
from typing import Dict

from django.db.models import Sum

from apps.accounts.models import LedgerEntry
from apps.balance_sheet.models import BalanceSheet
from apps.income_statement.models import IncomeStatement

from .models import Report


def _sum_entries(queryset, entry_type: str) -> Decimal:
    return (
        queryset.filter(entry_type=entry_type).aggregate(total=Sum("amount"))["total"]
        or Decimal("0")
    )


def build_report_payload(report_type: str, start_date, end_date) -> Dict:
    entries = LedgerEntry.objects.filter(entry_date__range=(start_date, end_date))
    income_entries = entries.filter(ledger__category__type="income")
    expense_entries = entries.filter(ledger__category__type="expense")
    asset_entries = entries.filter(ledger__category__type="asset")
    liability_entries = entries.filter(ledger__category__type="liability")

    income_total = _sum_entries(income_entries, LedgerEntry.TYPE_CREDIT)
    expense_total = _sum_entries(expense_entries, LedgerEntry.TYPE_DEBIT)
    asset_total = _sum_entries(asset_entries, LedgerEntry.TYPE_DEBIT) - _sum_entries(
        asset_entries, LedgerEntry.TYPE_CREDIT
    )
    liability_total = _sum_entries(
        liability_entries, LedgerEntry.TYPE_CREDIT
    ) - _sum_entries(liability_entries, LedgerEntry.TYPE_DEBIT)

    payload = {
        "income_total": str(income_total),
        "expense_total": str(expense_total),
        "asset_total": str(asset_total),
        "liability_total": str(liability_total),
        "profit_loss": str(income_total - expense_total),
    }

    if report_type == Report.TYPE_INCOME:
        return {"income_total": str(income_total)}
    if report_type == Report.TYPE_EXPENSE:
        return {"expense_total": str(expense_total)}
    if report_type == Report.TYPE_PROFIT_LOSS:
        return {
            "income_total": str(income_total),
            "expense_total": str(expense_total),
            "profit_loss": str(income_total - expense_total),
        }
    if report_type == Report.TYPE_BALANCE_SHEET:
        return {
            "assets": str(asset_total),
            "liabilities": str(liability_total),
            "equity": str(asset_total - liability_total),
        }
    return payload


def create_report(
    *,
    report_type: str,
    start_date,
    end_date,
    requested_by,
    export_format: str,
    filters: Dict | None = None,
) -> Report:
    data = build_report_payload(report_type, start_date, end_date)
    report = Report.objects.create(
        report_type=report_type,
        start_date=start_date,
        end_date=end_date,
        requested_by=requested_by,
        export_format=export_format,
        data=data,
        filters=filters or {},
    )

    if report_type == Report.TYPE_BALANCE_SHEET:
        BalanceSheet.objects.update_or_create(
            report=report,
            defaults={
                "total_assets": data.get("assets", "0"),
                "total_liabilities": data.get("liabilities", "0"),
                "total_equity": data.get("equity", "0"),
            },
        )
    if report_type in {Report.TYPE_INCOME, Report.TYPE_EXPENSE, Report.TYPE_PROFIT_LOSS}:
        IncomeStatement.objects.update_or_create(
            report=report,
            defaults={
                "total_revenue": data.get("income_total", "0"),
                "total_expense": data.get("expense_total", "0"),
                "net_income": data.get("profit_loss", "0"),
            },
        )

    return report


