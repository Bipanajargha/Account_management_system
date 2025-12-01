from django.contrib import admin

from .models import Receipt, Transaction, Voucher


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "ledger",
        "transaction_type",
        "payment_method",
        "amount",
        "status",
        "transaction_date",
    )
    list_filter = ("transaction_type", "payment_method", "status")
    search_fields = ("reference", "description")
    date_hierarchy = "transaction_date"


@admin.register(Voucher)
class VoucherAdmin(admin.ModelAdmin):
    list_display = ("id", "transaction", "voucher_type", "issued_at")
    list_filter = ("voucher_type",)


@admin.register(Receipt)
class ReceiptAdmin(admin.ModelAdmin):
    list_display = ("id", "transaction", "issued_to", "amount", "payment_method")
    search_fields = ("issued_to",)
