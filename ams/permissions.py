from rest_framework.permissions import BasePermission, SAFE_METHODS


ROLE_ADMIN = "admin"
ROLE_ACCOUNTANT = "accountant"
ROLE_MANAGER = "manager"
ROLE_CUSTOMER = "customer"


def get_user_role(user) -> str:
    """
    Map the Permissions field on AmsUser to a normalized role string.
    """
    if not user or not user.is_authenticated:
        return ""
    raw = (getattr(user, "Permissions", "") or "").lower()
    if not raw:
        raw = (getattr(user, "role", "") or "").lower()
    if not raw and hasattr(user, "effective_role"):
        raw = (user.effective_role or "").lower()
    if raw in {ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER, ROLE_CUSTOMER}:
        return raw
    # Fallback based on staff/superuser flags
    if getattr(user, "is_superuser", False):
        return ROLE_ADMIN
    if getattr(user, "is_staff", False):
        return ROLE_ACCOUNTANT
    return ROLE_CUSTOMER


class IsAdmin(BasePermission):
    """
    Allows access only to admin role users.
    """

    def has_permission(self, request, view) -> bool:
        return get_user_role(request.user) == ROLE_ADMIN


class RoleBasedPermission(BasePermission):
    """
    Generic role-based permission.

    Views can define:
      - required_roles = {'GET': [..], 'POST': [..], 'DEFAULT': [...]}  # by method
    or:
      - allowed_read_roles, allowed_write_roles
    """

    def has_permission(self, request, view) -> bool:
        role = get_user_role(request.user)
        if not role:
            return False

        action_roles = getattr(view, "action_allowed_roles", {})
        current_action = getattr(view, "action", None)
        if current_action and action_roles.get(current_action):
            return role in action_roles[current_action]

        # Method-specific configuration on the view
        required_roles = getattr(view, "required_roles", None)
        if isinstance(required_roles, dict):
            method = request.method.upper()
            roles_for_method = (
                required_roles.get(method)
                or required_roles.get("DEFAULT")
                or required_roles.get("*")
            )
            if roles_for_method is not None:
                return role in roles_for_method

        # Fallback: read vs write configuration
        if request.method in SAFE_METHODS:
            allowed_read = getattr(
                view,
                "allowed_read_roles",
                [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER],
            )
            return role in allowed_read

        allowed_write = getattr(
            view,
            "allowed_write_roles",
            [ROLE_ADMIN, ROLE_ACCOUNTANT],
        )
        return role in allowed_write