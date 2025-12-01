from rest_framework.routers import DefaultRouter

from .views import ReceiptViewSet, TransactionViewSet, VoucherViewSet

router = DefaultRouter()
router.register("transactions", TransactionViewSet, basename="transaction")
router.register("vouchers", VoucherViewSet, basename="voucher")
router.register("receipts", ReceiptViewSet, basename="receipt")

urlpatterns = router.urls


