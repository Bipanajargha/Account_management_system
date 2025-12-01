from rest_framework.routers import DefaultRouter

from .views import BillViewSet, InvoiceViewSet, PaymentRecordViewSet

router = DefaultRouter()
router.register("invoices", InvoiceViewSet, basename="invoice")
router.register("bills", BillViewSet, basename="bill")
router.register("payments", PaymentRecordViewSet, basename="payment-record")

urlpatterns = router.urls


