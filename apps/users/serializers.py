from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import AmsUser

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "AccountID",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
            "department",
            "phone_number",
            "employee_id",
            "timezone",
            "Status",
            "date_joined",
            "last_login",
        ]
        read_only_fields = ["AccountID", "date_joined", "last_login"]


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "password",
            "first_name",
            "last_name",
            "role",
            "department",
            "phone_number",
            "employee_id",
            "timezone",
        ]

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.Permissions = user.role or AmsUser.ROLE_CUSTOMER
        user.save()
        return user


class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["role", "Status"]


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value

    def validate(self, attrs):
        user = self.context["request"].user
        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError({"old_password": "Incorrect password."})
        return attrs

    def save(self, **kwargs):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user

