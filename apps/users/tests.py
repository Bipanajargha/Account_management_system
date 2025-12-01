from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase


class TestUserApi(APITestCase):
    def setUp(self):
        self.User = get_user_model()
        self.admin = self.User.objects.create_user(
            username="admin",
            email="admin@example.com",
            role=self.User.ROLE_ADMIN,
        )
        self.admin.set_password("AdminPass123")
        self.admin.save()

    def test_user_registration_and_login_flow(self):
        response = self.client.post(
            "/api/auth/register/",
            {
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "TestPass123",
                "first_name": "New",
                "last_name": "User",
                "role": self.User.ROLE_ACCOUNTANT,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        token_resp = self.client.post(
            "/api/auth/login/",
            {"username": "newuser", "password": "TestPass123"},
            format="json",
        )
        self.assertEqual(token_resp.status_code, status.HTTP_200_OK)
        self.assertIn("access", token_resp.data)

    def test_me_endpoint_returns_profile(self):
        self.client.force_authenticate(self.admin)
        response = self.client.get("/api/users/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "admin")

