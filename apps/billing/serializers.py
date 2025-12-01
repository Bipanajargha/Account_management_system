from rest_framework import serializers

from .models import Bill, Invoice, PaymentRecord


class InvoiceSerializer(serializers.ModelSerializer):
    total_due = serializers.DecimalField(max_digits=14, decimal_places=2, read_only=True)
    tax_amount = serializers.DecimalField(max_digits=14, decimal_places=2, read_only=True)
    discount_amount = serializers.DecimalField(max_digits=14, decimal_places=2, read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = Invoice
        fields = [
            "id",
            "number",
            "customer",
            "ledger",
            "description",
            "issue_date",
            "due_date",
            "subtotal",
            "tax_rate",
            "discount_rate",
            "status",
            "notes",
            "last_reminder_sent",
            "created_at",
            "total_due",
            "tax_amount",
            "discount_amount",
            "is_overdue",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "last_reminder_sent",
            "total_due",
            "tax_amount",
            "discount_amount",
            "is_overdue",
        ]


class BillSerializer(serializers.ModelSerializer):
    total_due = serializers.DecimalField(max_digits=14, decimal_places=2, read_only=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = Bill
        fields = [
            "id",
            "reference",
            "vendor_name",
            "ledger",
            "amount",
            "tax_rate",
            "discount_rate",
            "issued_date",
            "due_date",
            "status",
            "payment_method",
            "created_at",
            "total_due",
            "is_overdue",
        ]
        read_only_fields = ["id", "created_at", "total_due", "is_overdue"]


class PaymentRecordSerializer(serializers.ModelSerializer):
    target_type = serializers.SerializerMethodField()

    class Meta:
        model = PaymentRecord
        fields = [
            "id",
            "invoice",
            "bill",
            "amount",
            "method",
            "payment_date",
            "reference",
            "recorded_by",
            "created_at",
            "target_type",
        ]
        read_only_fields = ["id", "created_at", "recorded_by", "target_type"]

    def get_target_type(self, obj):
        if obj.invoice_id:
            return "invoice"
        if obj.bill_id:
            return "bill"
        return "unknown"

    def validate(self, attrs):
        if not attrs.get("invoice") and not attrs.get("bill"):
            raise serializers.ValidationError("Provide an invoice or bill to attach payment.")
        return attrs

    def create(self, validated_data):
        request = self.context.get("request")
        if request and getattr(request, "user", None):
            validated_data["recorded_by"] = request.user
        return super().create(validated_data)


