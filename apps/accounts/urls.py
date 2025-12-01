from django.urls import path
from .views import AccountCategoryViewSet, LedgerAccountViewSet, LedgerEntryViewSet, AccountBalanceViewSet

urlpatterns = [
    path('categories/', AccountCategoryViewSet.as_view({'get': 'list', 'post': 'create'}), name='account-category-list'),
    path('categories/<int:pk>/', AccountCategoryViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='account-category-detail'),
    path('ledgers/', LedgerAccountViewSet.as_view({'get': 'list', 'post': 'create'}), name='ledger-account-list'),
    path('ledgers/<int:pk>/', LedgerAccountViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='ledger-account-detail'),
    path('entries/', LedgerEntryViewSet.as_view({'get': 'list', 'post': 'create'}), name='ledger-entry-list'),
    path('entries/<int:pk>/', LedgerEntryViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='ledger-entry-detail'),
    path('balances/', AccountBalanceViewSet.as_view({'get': 'list', 'post': 'create'}), name='account-balance-list'),
    path('balances/<int:pk>/', AccountBalanceViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='account-balance-detail'),
]