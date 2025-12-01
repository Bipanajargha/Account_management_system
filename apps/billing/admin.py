from django.contrib import admin

from .models import Bill, Invoice, PaymentRecord


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ("number", "customer", "ledger", "status", "due_date", "subtotal")
    list_filter = ("status", "ledger__category__type")
    search_fields = ("number", "customer__username", "description")


@admin.register(Bill)
class BillAdmin(admin.ModelAdmin):
    list_display = ("reference", "vendor_name", "status", "due_date", "amount")
    list_filter = ("status", "payment_method")
    search_fields = ("reference", "vendor_name")


@admin.register(PaymentRecord)
class PaymentRecordAdmin(admin.ModelAdmin):
    list_display = ("id", "invoice", "bill", "amount", "method", "payment_date")
    list_filter = ("method",)
    search_fields = ("reference",)