from django.contrib import admin

from .models import AccountBalance, AccountCategory, LedgerAccount, LedgerEntry


@admin.register(AccountCategory)
class AccountCategoryAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "type", "created_at")
    search_fields = ("code", "name")
    list_filter = ("type",)


@admin.register(LedgerAccount)
class LedgerAccountAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "category", "is_active", "created_at")
    search_fields = ("code", "name")
    list_filter = ("category__type", "is_active")


@admin.register(LedgerEntry)
class LedgerEntryAdmin(admin.ModelAdmin):
    list_display = (
        "ledger",
        "entry_type",
        "amount",
        "payment_method",
        "entry_date",
    )
    list_filter = ("entry_type", "payment_method")
    search_fields = ("ledger__code", "reference")


@admin.register(AccountBalance)
class AccountBalanceAdmin(admin.ModelAdmin):
    list_display = ("ledger", "balance", "updated_at")
