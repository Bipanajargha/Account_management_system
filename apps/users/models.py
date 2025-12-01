# apps/users/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models


class AmsUser(AbstractUser):
    """
    Custom user with explicit roles and account metadata.
    """

    ROLE_ADMIN = "admin"
    ROLE_ACCOUNTANT = "accountant"
    ROLE_MANAGER = "manager"
    ROLE_CUSTOMER = "customer"

    ROLE_CHOICES = [
        (ROLE_ADMIN, "Admin"),
        (ROLE_ACCOUNTANT, "Accountant"),
        (ROLE_MANAGER, "Manager"),
        (ROLE_CUSTOMER, "Customer"),
    ]

    STATUS_ACTIVE = "active"
    STATUS_INACTIVE = "inactive"
    STATUS_SUSPENDED = "suspended"

    STATUS_CHOICES = [
        (STATUS_ACTIVE, "Active"),
        (STATUS_INACTIVE, "Inactive"),
        (STATUS_SUSPENDED, "Suspended"),
    ]

    AccountID = models.AutoField(primary_key=True)
    employee_id = models.CharField(max_length=64, blank=True)
    role = models.CharField(max_length=32, choices=ROLE_CHOICES, default=ROLE_CUSTOMER)
    department = models.CharField(max_length=128, blank=True)
    phone_number = models.CharField(max_length=32, blank=True)
    Permissions = models.CharField(max_length=100, default=ROLE_CUSTOMER)
    Status = models.CharField(max_length=32, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    timezone = models.CharField(max_length=64, default="UTC")

    groups = models.ManyToManyField(
        "auth.Group",
        related_name="ams_users",
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="ams_users",
        blank=True,
    )

    class Meta:
        verbose_name = "AMS User"
        verbose_name_plural = "AMS Users"

    def __str__(self) -> str:
        display_name = self.get_full_name().strip() or self.username
        return f"{display_name} ({self.effective_role})"

    @property
    def effective_role(self) -> str:
        """
        Normalize the stored role value so we have a single source of truth.
        """
        return (self.role or self.Permissions or self.ROLE_CUSTOMER).lower()

    def save(self, *args, **kwargs):
        if not self.role and self.Permissions:
            self.role = self.Permissions
        if not self.Permissions:
            self.Permissions = self.role
        self.Permissions = (self.Permissions or self.ROLE_CUSTOMER).lower()
        self.role = (self.role or self.Permissions or self.ROLE_CUSTOMER).lower()
        super().save(*args, **kwargs)

    def has_role(self, *roles: str) -> bool:
        """
        Helper used by permission checks to verify if the user has any of the provided roles.
        """

        normalized = self.effective_role
        lowered_roles = {role.lower() for role in roles}
        return normalized in lowered_roles