from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import AmsUser


@admin.register(AmsUser)
class AmsUserAdmin(UserAdmin):
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "role",
        "Status",
        "is_staff",
    )
    list_filter = ("role", "Status", "is_staff", "is_superuser", "is_active")
    search_fields = ("username", "email", "first_name", "last_name", "employee_id")
    ordering = ("-date_joined",)

    fieldsets = UserAdmin.fieldsets + (
        (
            "Account Details",
            {
                "fields": (
                    "employee_id",
                    "role",
                    "department",
                    "phone_number",
                    "Status",
                    "timezone",
                )
            },
        ),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        (
            "Account Details",
            {
                "fields": (
                    "employee_id",
                    "role",
                    "department",
                    "phone_number",
                    "Status",
                    "timezone",
                )
            },
        ),
    )