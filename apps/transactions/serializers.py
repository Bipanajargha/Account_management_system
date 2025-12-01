from rest_framework import serializers

from .models import Receipt, Transaction, Voucher


class TransactionSerializer(serializers.ModelSerializer):
    ledger_code = serializers.CharField(source="ledger.code", read_only=True)
    created_by_username = serializers.CharField(source="created_by.username", read_only=True)
    approved_by_username = serializers.CharField(source="approved_by.username", read_only=True)

    class Meta:
        model = Transaction
        fields = [
            "id",
            "ledger",
            "ledger_code",
            "transaction_type",
            "payment_method",
            "amount",
            "currency",
            "description",
            "reference",
            "transaction_date",
            "status",
            "created_by",
            "created_by_username",
            "approved_by",
            "approved_by_username",
            "approved_at",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "created_by",
            "created_by_username",
            "approved_by",
            "approved_by_username",
            "approved_at",
            "created_at",
            "ledger_code",
        ]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and getattr(request, "user", None):
            validated_data["created_by"] = request.user
        return super().create(validated_data)


class VoucherSerializer(serializers.ModelSerializer):
    transaction_detail = TransactionSerializer(source="transaction", read_only=True)

    class Meta:
        model = Voucher
        fields = ["id", "transaction", "transaction_detail", "voucher_type", "issued_at", "notes"]
        read_only_fields = ["id", "issued_at", "transaction_detail"]


class ReceiptSerializer(serializers.ModelSerializer):
    transaction_detail = TransactionSerializer(source="transaction", read_only=True)

    class Meta:
        model = Receipt
        fields = [
            "id",
            "transaction",
            "transaction_detail",
            "issued_to",
            "amount",
            "issued_at",
            "payment_method",
            "details",
        ]
        read_only_fields = ["id", "issued_at", "transaction_detail"]


