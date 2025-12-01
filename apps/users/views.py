from django.contrib.auth import get_user_model
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

# Assumed internal imports
from ams.permissions import (
    ROLE_ACCOUNTANT,
    ROLE_ADMIN,
    ROLE_MANAGER,
    RoleBasedPermission,
)
from apps.notifications.utils import log_audit
from .serializers import (
    PasswordChangeSerializer,
    UserCreateSerializer,
    UserSerializer,
)

AmsUser = get_user_model()

class AmsTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT Serializer with safety checks for custom claims.
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # --- FIX: Safe extraction of effective_role ---
        # 1. Get attribute, default to empty string
        role = getattr(user, "effective_role", "")
        
        # 2. If it's a method (e.g., @property missing), call it
        if callable(role):
            try:
                role = role()
            except Exception:
                role = ""
        
        # 3. Force string to ensure JSON serialization works
        token["role"] = str(role)
        token["username"] = user.get_username()
        
        return token

class AmsTokenObtainPairView(TokenObtainPairView):
    """
    Custom Login View.
    Authentication is disabled to prevent CSRF errors.
    Audit logging is wrapped in try/except to prevent 500 errors.
    """
    serializer_class = AmsTokenObtainPairSerializer
    authentication_classes = [] 
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        # 1. Perform standard login logic
        try:
            response = super().post(request, *args, **kwargs)
        except Exception as e:
            # If token generation crashes, print error to console and return 500
            print(f"!!! LOGIN CRASH (Token Generation): {e}")
            return Response(
                {"detail": "Internal error during token generation."}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 2. Log Audit only on success
        if response.status_code == status.HTTP_200_OK:
            try:
                # Safely get username from request
                username = request.data.get("username") or request.data.get(AmsUser.USERNAME_FIELD)
                
                # Retrieve user
                if username:
                    user = AmsUser.objects.filter(username=username).first()
                    
                    if user:
                        log_audit(
                            user=user,
                            action="login",
                            entity_type="auth",
                            entity_id=str(user.pk),
                            metadata={"ip": request.META.get("REMOTE_ADDR")},
                        )
            except Exception as e:
                # --- FIX: Do not crash login if logging fails ---
                print(f"!!! LOGIN WARNING (Audit Log Failed): {e}")
                # We do NOT return an error here, so the user can still log in.

        return response


class UserViewSet(viewsets.ModelViewSet):
    queryset = AmsUser.objects.all().order_by("-date_joined")
    serializer_class = UserSerializer
    permission_classes = [RoleBasedPermission]
    
    allowed_read_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_MANAGER]
    allowed_write_roles = [ROLE_ADMIN, ROLE_ACCOUNTANT]
    
    filterset_fields = ["role", "Status", "department"]
    search_fields = ["username", "email", "first_name", "last_name", "employee_id"]
    ordering_fields = ["date_joined", "last_login", "username"]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]

    def get_serializer_class(self):
        if self.action in {"create", "register"}:
            return UserCreateSerializer
        return UserSerializer

    def get_permissions(self):
        if self.action in {"register"}:
            return [permissions.AllowAny()]
        if self.action in {"me", "change_password"}:
            return [permissions.IsAuthenticated()]
        return super().get_permissions()

    def perform_create(self, serializer):
        user = serializer.save()
        try:
            log_audit(
                user=self.request.user if self.request.user.is_authenticated else None,
                action="create",
                entity_type="user",
                entity_id=str(user.pk),
                metadata={"username": user.username},
            )
        except Exception as e:
            print(f"Audit Error (User Create): {e}")

    def perform_update(self, serializer):
        user = serializer.save()
        try:
            log_audit(
                user=self.request.user,
                action="update",
                entity_type="user",
                entity_id=str(user.pk),
            )
        except Exception as e:
            print(f"Audit Error (User Update): {e}")

    def perform_destroy(self, instance):
        entity_id = str(instance.pk)
        super().perform_destroy(instance)
        try:
            log_audit(
                user=self.request.user,
                action="delete",
                entity_type="user",
                entity_id=entity_id,
            )
        except Exception as e:
            print(f"Audit Error (User Delete): {e}")

    @action(detail=False, methods=["post"], permission_classes=[permissions.AllowAny])
    def register(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        try:
            log_audit(
                user=user,
                action="create",
                entity_type="user_registration",
                entity_id=str(user.pk),
                metadata={"username": user.username},
            )
        except Exception as e:
            print(f"Audit Error (Register): {e}")
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get", "patch"], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        if request.method == "GET":
            return Response(UserSerializer(request.user).data)

        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        serializer = PasswordChangeSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Password updated."}, status=status.HTTP_200_OK)


class RegistrationView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        try:
            log_audit(
                user=user,
                action="create",
                entity_type="user_registration",
                entity_id=str(user.pk),
                metadata={"username": user.username},
            )
        except Exception as e:
            print(f"Audit Error (RegistrationView): {e}")
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)