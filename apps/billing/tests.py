from datetime import date, timedelta

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.accounts.models import AccountCategory, LedgerAccount


class BillingApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="billingadmin",
            email="billing@example.com",
            role=User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()
        self.client.force_authenticate(self.admin)

        self.category = AccountCategory.objects.create(
            name="Income Accounts",
            code="INC-001",
            type="income",
        )
        self.ledger = LedgerAccount.objects.create(
            name="Sales Revenue",
            code="REV-001",
            category=self.category,
            owner=self.admin,
        )

    def test_invoice_and_payment_workflow(self):
        invoice_resp = self.client.post(
            "/api/billing/invoices/",
            {
                "number": "INV-1001",
                "customer": self.admin.id,
                "ledger": self.ledger.id,
                "description": "Consulting services",
                "issue_date": date.today().isoformat(),
                "due_date": (date.today() + timedelta(days=7)).isoformat(),
                "subtotal": "1500.00",
                "tax_rate": "5.00",
                "discount_rate": "0",
            },
            format="json",
        )
        self.assertEqual(invoice_resp.status_code, status.HTTP_201_CREATED)
        invoice_id = invoice_resp.data["id"]

        payment_resp = self.client.post(
            "/api/billing/payments/",
            {
                "invoice": invoice_id,
                "amount": "1500.00",
                "method": "bank",
                "payment_date": date.today().isoformat(),
            },
            format="json",
        )
        self.assertEqual(payment_resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(payment_resp.data["invoice"], invoice_id)

