from django.contrib import admin
from django.urls import include, path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

# Import views
from apps.accounts.views import (
    AccountBalanceViewSet, AccountCategoryViewSet, LedgerAccountViewSet, LedgerEntryViewSet,
)
from apps.billing.views import BillViewSet, InvoiceViewSet, PaymentRecordViewSet
from apps.notifications.views import AuditLogViewSet, NotificationViewSet
from apps.reports.views import ReportViewSet
from apps.transactions.views import ReceiptViewSet, TransactionViewSet, VoucherViewSet
from apps.users.views import AmsTokenObtainPairView, RegistrationView, UserViewSet

# Router Setup
router = DefaultRouter()
router.register("users", UserViewSet, basename="user")
router.register("accounts/categories", AccountCategoryViewSet, basename="account-category")
router.register("accounts/ledgers", LedgerAccountViewSet, basename="ledger-account")
router.register("accounts/entries", LedgerEntryViewSet, basename="ledger-entry")
router.register("accounts/balances", AccountBalanceViewSet, basename="account-balance")
router.register("billing/invoices", InvoiceViewSet, basename="invoice")
router.register("billing/bills", BillViewSet, basename="bill")
router.register("billing/payments", PaymentRecordViewSet, basename="payment-record")
router.register("transactions", TransactionViewSet, basename="transaction")
router.register("vouchers", VoucherViewSet, basename="voucher")
router.register("receipts", ReceiptViewSet, basename="receipt")
router.register("reports", ReportViewSet, basename="report")
router.register("notifications", NotificationViewSet, basename="notification")
router.register("audit-logs", AuditLogViewSet, basename="audit-log")

schema_view = get_schema_view(
    openapi.Info(
        title="Account Management System API",
        default_version="v1",
        description="Comprehensive AMS backend built with Django REST Framework.",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("admin/", admin.site.urls),

    # --- FIX: Place custom Auth URLs BEFORE the DRF include ---
    path("api/auth/login/", AmsTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/auth/register/", RegistrationView.as_view(), name="user_register"),

    # This include contains a generic 'login/' route that was shadowing your custom one
    path("api/auth/", include("rest_framework.urls")), 

    path("api/", include(router.urls)),
    
    # Docs
    path("api/docs/", schema_view.with_ui("swagger", cache_timeout=0), name="api_docs"),
    path("api/redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="api_redoc"),
]