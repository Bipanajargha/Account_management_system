from rest_framework import serializers

from .models import AccountBalance, AccountCategory, LedgerAccount, LedgerEntry


class AccountCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountCategory
        fields = ["id", "name", "code", "type", "description", "created_at"]
        read_only_fields = ["id", "created_at"]


class LedgerAccountSerializer(serializers.ModelSerializer):
    category_detail = AccountCategorySerializer(source="category", read_only=True)
    balance = serializers.SerializerMethodField()

    class Meta:
        model = LedgerAccount
        fields = [
            "id",
            "name",
            "code",
            "category",
            "category_detail",
            "owner",
            "description",
            "is_active",
            "created_at",
            "balance",
        ]
        read_only_fields = ["id", "created_at", "balance"]

    def get_balance(self, obj):
        if hasattr(obj, "balance") and obj.balance:
            return obj.balance.balance
        return 0


class LedgerEntrySerializer(serializers.ModelSerializer):
    ledger_detail = LedgerAccountSerializer(source="ledger", read_only=True)

    class Meta:
        model = LedgerEntry
        fields = [
            "id",
            "ledger",
            "ledger_detail",
            "entry_type",
            "amount",
            "payment_method",
            "description",
            "reference",
            "entry_date",
            "created_by",
            "created_at",
        ]
        read_only_fields = ["id", "created_at", "created_by"]

    def create(self, validated_data):
        request = self.context.get("request")
        if request and getattr(request, "user", None):
            validated_data["created_by"] = request.user
        return super().create(validated_data)


class AccountBalanceSerializer(serializers.ModelSerializer):
    ledger_detail = LedgerAccountSerializer(source="ledger", read_only=True)

    class Meta:
        model = AccountBalance
        fields = ["ledger", "ledger_detail", "balance", "updated_at"]
        read_only_fields = ["balance", "updated_at"]
