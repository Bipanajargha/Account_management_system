from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from .models import Notification


class NotificationApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="notifyadmin",
            email="notify@example.com",
            role=User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()

        self.manager = User.objects.create_user(
            username="notifymanager",
            email="notifymanager@example.com",
            role=User.ROLE_MANAGER,
        )
        self.manager.set_password("ManagerPass123")
        self.manager.save()

        Notification.objects.create(
            user=self.manager,
            message="Invoice overdue",
            level=Notification.LEVEL_WARNING,
        )

    def test_admin_can_list_notifications(self):
        self.client.force_authenticate(self.admin)
        response = self.client.get("/api/notifications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_manager_sees_only_own_notifications(self):
        self.client.force_authenticate(self.manager)
        response = self.client.get("/api/notifications/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

