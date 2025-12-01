from datetime import date

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.accounts.models import AccountCategory, LedgerAccount


class TransactionApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="txnadmin",
            email="txn@example.com",
            role=User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()
        self.manager = User.objects.create_user(
            username="manager",
            email="manager@example.com",
            role=User.ROLE_MANAGER,
        )
        self.manager.set_password("ManagerPass123")
        self.manager.save()

        category = AccountCategory.objects.create(
            name="Cash",
            code="CASH",
            type="asset",
        )
        self.ledger = LedgerAccount.objects.create(
            name="Main Cash",
            code="CASH-LEDGER",
            category=category,
            owner=self.admin,
        )

    def test_transaction_create_and_approve(self):
        self.client.force_authenticate(self.admin)
        resp = self.client.post(
            "/api/transactions/",
            {
                "ledger": self.ledger.id,
                "transaction_type": "incoming",
                "payment_method": "cash",
                "amount": "500.00",
                "description": "Seed funding",
                "transaction_date": date.today().isoformat(),
            },
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        transaction_id = resp.data["id"]

        self.client.force_authenticate(self.manager)
        approve_resp = self.client.post(f"/api/transactions/{transaction_id}/approve/")
        self.assertEqual(approve_resp.status_code, status.HTTP_200_OK)

