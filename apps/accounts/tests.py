from decimal import Decimal

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.accounts.models import AccountCategory, LedgerAccount


class AccountsApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="acctadmin",
            email="acct@example.com",
            role=User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()
        self.client.force_authenticate(self.admin)

    def test_create_category_ledger_and_entry(self):
        cat_resp = self.client.post(
            "/api/accounts/categories/",
            {"name": "Cash Assets", "code": "CA100", "type": "asset"},
            format="json",
        )
        self.assertEqual(cat_resp.status_code, status.HTTP_201_CREATED)
        category_id = cat_resp.data["id"]

        ledger_resp = self.client.post(
            "/api/accounts/ledgers/",
            {
                "name": "Cash On Hand",
                "code": "CASH-01",
                "category": category_id,
                "description": "Primary cash ledger",
            },
            format="json",
        )
        self.assertEqual(ledger_resp.status_code, status.HTTP_201_CREATED)
        ledger_id = ledger_resp.data["id"]

        entry_resp = self.client.post(
            "/api/accounts/entries/",
            {
                "ledger": ledger_id,
                "entry_type": "debit",
                "amount": "1000.00",
                "payment_method": "cash",
                "description": "Initial funding",
            },
            format="json",
        )
        self.assertEqual(entry_resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(entry_resp.status_code, status.HTTP_201_CREATED)
        ledger = LedgerAccount.objects.get(id=ledger_id)
        self.assertEqual(ledger.balance.balance, Decimal("1000.00"))

