from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken


from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes


from django.conf import settings
from django.shortcuts import redirect


from .serializers import LoginSerializer, RegisterSerializer, SetPasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, ChangePasswordSerializer
from .models import User, UserSession, AuditLog
from .tokens import verify_email_verification_token, generate_email_verification_token
from .emails import send_verification_email, send_password_reset_email
from .audit import log_event
from .services import get_or_create_user_from_sso
from .sso import exchange_github_code, exchange_google_code
from .utils import decode_state, encode_state, generate_password_reset_token, verify_password_reset_token
from .permissions import require_user_permission
from .throttles import LoginThrottle, PasswordResetThrottle, SSOThrottle


@extend_schema(
    tags=["Auth"],
    summary="Register a new user",
    request=RegisterSerializer,
    responses={201: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    token = generate_email_verification_token(user)
    send_verification_email(user, token)

    log_event(
        actor=user,
        action="register",
        resource_type="user",
        resource_id=user.id,
        request=request,
    )

    return Response(
        {
            "detail": "Registration successful. Please verify your email."
        },
        status=status.HTTP_201_CREATED,
    )


@extend_schema(
    tags=["Auth"],
    summary="User login",
    request=LoginSerializer,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([LoginThrottle])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data["user"]
    refresh = RefreshToken.for_user(user)

    # Create session
    UserSession.objects.create(
        user=user,
        refresh_token_jti=refresh["jti"],
        ip_address=request.META.get("REMOTE_ADDR"),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )

    log_event(
        actor=user,
        action="login",
        resource_type="auth",
        request=request,
    )

    return Response(
        {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        },
        status=status.HTTP_200_OK,
    )


@extend_schema(
    tags=["Auth"],
    summary="User logout",
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
    except InvalidToken:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

    UserSession.objects.filter(
        refresh_token_jti=token["jti"],
        user=request.user,
    ).update(is_active=False)

    log_event(
        actor=request.user,
        action="logout",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Logged out"})


@extend_schema(
    tags=["Auth"],
    summary="Logout from all devices",
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_all_view(request):
    UserSession.objects.filter(
        user=request.user,
        is_active=True,
    ).update(is_active=False)

    return Response({"detail": "Logged out from all devices"})


@extend_schema(
    tags=["Auth"],
    summary="Refresh access token",
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def token_refresh_view(request):
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
    except InvalidToken:
        raise AuthenticationFailed("Invalid refresh token")

    jti = token["jti"]

    session = UserSession.objects.filter(
        refresh_token_jti=jti,
        is_active=True,
    ).first()

    if not session:
        raise AuthenticationFailed("Session expired or revoked")

    # Update usage
    session.save(update_fields=["last_used_at"])

    return Response(
        {
            "access": str(token.access_token),
        }
    )


@extend_schema(
    tags=["User Profile"],
    summary="Get current user details",
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me_view(request):
    user = request.user
    return Response(
        {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "is_email_verified": user.is_email_verified,
        }
    )


@extend_schema(
    tags=["Account Management"],
    summary="Verify email address",
    parameters=[
        OpenApiParameter("token", OpenApiTypes.STR, OpenApiParameter.QUERY, required=True),
    ],
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([AllowAny])
def verify_email_view(request):
    token = request.query_params.get("token")

    if not token:
        return Response({"error": "Token missing"}, status=status.HTTP_400_BAD_REQUEST)

    user_id = verify_email_verification_token(token)

    if not user_id:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_email_verified:
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])

    return Response({"detail": "Email verified successfully"})


@extend_schema(
    tags=["Account Management"],
    summary="Resend verification email",
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def resend_verification_view(request):
    email = request.data.get("email")

    if not email:
        return Response({"error": "Email required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"detail": "If the email exists, verification was sent"},
            status=200,
        )

    if user.is_email_verified:
        return Response({"error": "Email already verified"}, status=status.HTTP_400_BAD_REQUEST)

    token = generate_email_verification_token(user)
    send_verification_email(user, token)

    return Response({"detail": "Verification email sent"})


@extend_schema(
    tags=["Auth"],
    summary="Initiate SSO login",
    parameters=[
        OpenApiParameter("provider", OpenApiTypes.STR, OpenApiParameter.PATH, enum=["google", "github"]),
    ],
    request=OpenApiTypes.OBJECT,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([SSOThrottle])
def sso_login_view(request, provider):
    next_url = request.data.get("next", "/dashboard")

    state = encode_state({
        "provider": provider,
        "next": next_url,
    })

    if provider == "google":
        auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={settings.GOOGLE_CLIENT_ID}"
            f"&redirect_uri={settings.SSO_REDIRECT_URI}"
            f"&response_type=code"
            f"&scope=openid email profile"
            f"&state={state}"
        )

    elif provider == "github":
        auth_url = (
            "https://github.com/login/oauth/authorize"
            f"?client_id={settings.GITHUB_CLIENT_ID}"
            f"&redirect_uri={settings.SSO_REDIRECT_URI}"
            f"&scope=user:email"
            f"&state={state}"
        )

    else:
        return Response({"error": "Unsupported provider"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({"auth_url": auth_url})


@extend_schema(
    tags=["Auth"],
    summary="SSO Callback",
    parameters=[
        OpenApiParameter("code", OpenApiTypes.STR, OpenApiParameter.QUERY),
        OpenApiParameter("state", OpenApiTypes.STR, OpenApiParameter.QUERY),
    ],
    responses={302: None},
)
@api_view(["GET"])
@permission_classes([AllowAny])
def sso_callback_view(request):
    code = request.GET.get("code")
    state = request.GET.get("state")

    if not code or not state:
        return Response({"error": "Invalid SSO callback"}, status=status.HTTP_400_BAD_REQUEST)

    state_data = decode_state(state)
    if not state_data:
        return Response({"error": "Invalid or expired state"}, status=status.HTTP_400_BAD_REQUEST)

    provider = state_data.get("provider")
    next_url = state_data.get("next", "/")

    if provider == "google":
        data = exchange_google_code(
            code,
            settings.SSO_REDIRECT_URI,
            settings.GOOGLE_CLIENT_ID,
            settings.GOOGLE_CLIENT_SECRET,
        )
        provider_user_id = data["id"]
        email = data["email"]
        name = data.get("name", "")

    elif provider == "github":
        data = exchange_github_code(
            code,
            settings.SSO_REDIRECT_URI,
            settings.GITHUB_CLIENT_ID,
            settings.GITHUB_CLIENT_SECRET,
        )
        provider_user_id = data["id"]
        email = data["email"]
        name = data["name"]

    else:
        return Response({"error": "Unsupported provider"}, status=status.HTTP_400_BAD_REQUEST)

    user, created = get_or_create_user_from_sso(
        provider=provider,
        provider_user_id=provider_user_id,
        email=email,
        name=name,
    )

    refresh = RefreshToken.for_user(user)

    UserSession.objects.create(
        user=user,
        refresh_token_jti=refresh["jti"],
        ip_address=request.META.get("REMOTE_ADDR"),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )

    log_event(
        actor=user,
        action=f"sso.login.{provider}",
        resource_type="auth",
        request=request,
    )

    redirect_url = (
        f"{settings.FRONTEND_URL}{next_url}"
        f"?access={refresh.access_token}&refresh={refresh}"
        f"&new_user={str(created).lower()}"
    )

    return redirect(redirect_url)


@extend_schema(
    tags=["Account Management"],
    summary="Set account password",
    description="For SSO users who want to add a password login option",
    request=SetPasswordSerializer,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def set_password_view(request):
    serializer = SetPasswordSerializer(
        data=request.data,
        context={"request": request},
    )
    serializer.is_valid(raise_exception=True)

    user = request.user
    user.set_password(serializer.validated_data["password"])
    user.save(update_fields=["password"])

    log_event(
        actor=user,
        action="password.set",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Password set successfully"})


@extend_schema(
    tags=["Account Management"],
    summary="Forgot password request",
    request=ForgotPasswordSerializer,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetThrottle])
def forgot_password_view(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]

    user = User.objects.filter(email=email).first()
    if user and user.has_usable_password():
        token = generate_password_reset_token(user)
        reset_link = (
            f"{settings.FRONTEND_URL}/reset-password"
            f"?token={token}"
        )
        send_password_reset_email(user.email, reset_link)

        log_event(
            actor=user,
            action="password.reset.request",
            resource_type="auth",
            request=request,
        )

    # Always return same response
    return Response(
        {"detail": "If the email exists, a reset link was sent"}
    )


@extend_schema(
    tags=["Account Management"],
    summary="Reset password with token",
    request=ResetPasswordSerializer,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password_view(request):
    serializer = ResetPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user_id = verify_password_reset_token(
        serializer.validated_data["token"]
    )

    if not user_id:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(serializer.validated_data["password"])
    user.save(update_fields=["password"])

    log_event(
        actor=user,
        action="password.reset.complete",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Password reset successful"})


@extend_schema(
    tags=["Account Management"],
    summary="Change account password",
    request=ChangePasswordSerializer,
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    serializer = ChangePasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = request.user

    if not user.has_usable_password():
        return Response(
            {"error": "Password login not enabled for this account"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not user.check_password(
        serializer.validated_data["old_password"]
    ):
        return Response({"error": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(serializer.validated_data["new_password"])
    user.save(update_fields=["password"])

    log_event(
        actor=user,
        action="password.change",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Password changed successfully"})


# Sample View for User Permissions
#### START #### 
@extend_schema(
    tags=["Internal"],
    summary="Internal dashboard data",
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def internal_dashboard_view(request):
    require_user_permission(
        request.user,
        "internal.dashboard.view",
    )

    return Response(
        {
            "message": "Welcome to the internal dashboard",
            "user": request.user.email,
            "role": request.user.role,
        }
    )

@extend_schema(
    tags=["Internal"],
    summary="List all users",
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def internal_users_list_view(request):
    require_user_permission(
        request.user,
        "internal.users.read",
    )

    users = User.objects.all().only("id", "email", "role", "is_active")

    return Response(
        [
            {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
            }
            for user in users
        ]
    )

@extend_schema(
    tags=["Internal"],
    summary="List audit logs",
    responses={200: OpenApiTypes.OBJECT},
)
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def internal_audit_logs_view(request):
    require_user_permission(
        request.user,
        "internal.audit.read",
    )

    logs = (
        AuditLog.objects
        .select_related("actor")
        .order_by("-created_at")[:50]
    )

    return Response(
        [
            {
                "id": log.id,
                "actor": log.actor.email if log.actor else None,
                "action": log.action,
                "resource_type": log.resource_type,
                "created_at": log.created_at,
            }
            for log in logs
        ]
    )

#### END #### 