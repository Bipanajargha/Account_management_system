from datetime import date, timedelta

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from apps.accounts.models import AccountCategory, LedgerAccount, LedgerEntry


class ReportApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="reportadmin",
            email="report@example.com",
            role=User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()
        self.client.force_authenticate(self.admin)

        income_category = AccountCategory.objects.create(
            name="Income",
            code="INC",
            type="income",
        )
        expense_category = AccountCategory.objects.create(
            name="Expenses",
            code="EXP",
            type="expense",
        )
        self.income_ledger = LedgerAccount.objects.create(
            name="Sales",
            code="INC-001",
            category=income_category,
            owner=self.admin,
        )
        self.expense_ledger = LedgerAccount.objects.create(
            name="Utilities",
            code="EXP-001",
            category=expense_category,
            owner=self.admin,
        )

        LedgerEntry.objects.create(
            ledger=self.income_ledger,
            entry_type="credit",
            amount="2000.00",
            payment_method="bank",
            description="Income entry",
        )
        LedgerEntry.objects.create(
            ledger=self.expense_ledger,
            entry_type="debit",
            amount="500.00",
            payment_method="cash",
            description="Expense entry",
        )

    def test_generate_profit_and_loss_report(self):
        resp = self.client.post(
            "/api/reports/",
            {
                "report_type": "profit_loss",
                "start_date": (date.today() - timedelta(days=30)).isoformat(),
                "end_date": date.today().isoformat(),
                "export_format": "pdf",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("profit_loss", resp.data["data"])
        report_id = resp.data["id"]

        export_resp = self.client.get(f"/api/reports/{report_id}/export/")
        self.assertEqual(export_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(export_resp.data["format"], "pdf")
