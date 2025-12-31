from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken


from django.conf import settings
from django.shortcuts import redirect


from .serializers import LoginSerializer, RegisterSerializer, SetPasswordSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, ChangePasswordSerializer
from .models import User, UserSession
from .tokens import verify_email_verification_token, generate_email_verification_token
from .emails import send_verification_email, send_password_reset_email
from .audit import log_event
from .services import get_or_create_user_from_sso
from .sso import exchange_github_code, exchange_google_code
from .utils import decode_state, encode_state, generate_password_reset_token, verify_password_reset_token


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


@api_view(["POST"])
@permission_classes([AllowAny])
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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response({"detail": "Refresh token required"}, status=400)

    try:
        token = RefreshToken(refresh_token)
    except InvalidToken:
        return Response({"detail": "Invalid token"}, status=400)

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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_all_view(request):
    UserSession.objects.filter(
        user=request.user,
        is_active=True,
    ).update(is_active=False)

    return Response({"detail": "Logged out from all devices"})


@api_view(["POST"])
@permission_classes([AllowAny])
def token_refresh_view(request):
    refresh_token = request.data.get("refresh")

    if not refresh_token:
        return Response({"detail": "Refresh token required"}, status=400)

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


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_email_view(request):
    token = request.query_params.get("token")

    if not token:
        return Response({"detail": "Token missing"}, status=400)

    user_id = verify_email_verification_token(token)

    if not user_id:
        return Response({"detail": "Invalid or expired token"}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"detail": "User not found"}, status=404)

    if not user.is_email_verified:
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])

    return Response({"detail": "Email verified successfully"})


@api_view(["POST"])
@permission_classes([AllowAny])
def resend_verification_view(request):
    email = request.data.get("email")

    if not email:
        return Response({"detail": "Email required"}, status=400)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response(
            {"detail": "If the email exists, verification was sent"},
            status=200,
        )

    if user.is_email_verified:
        return Response({"detail": "Email already verified"}, status=400)

    token = generate_email_verification_token(user)
    send_verification_email(user, token)

    return Response({"detail": "Verification email sent"})


@api_view(["POST"])
@permission_classes([AllowAny])
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
        return Response({"detail": "Unsupported provider"}, status=400)

    return Response({"auth_url": auth_url})


@api_view(["GET"])
@permission_classes([AllowAny])
def sso_callback_view(request):
    code = request.GET.get("code")
    state = request.GET.get("state")

    if not code or not state:
        return Response({"detail": "Invalid SSO callback"}, status=400)

    state_data = decode_state(state)
    if not state_data:
        return Response({"detail": "Invalid or expired state"}, status=400)

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
        return Response({"detail": "Unsupported provider"}, status=400)

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


@api_view(["POST"])
@permission_classes([AllowAny])
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


@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password_view(request):
    serializer = ResetPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user_id = verify_password_reset_token(
        serializer.validated_data["token"]
    )

    if not user_id:
        return Response({"detail": "Invalid or expired token"}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({"detail": "Invalid token"}, status=400)

    user.set_password(serializer.validated_data["password"])
    user.save(update_fields=["password"])

    log_event(
        actor=user,
        action="password.reset.complete",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Password reset successful"})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    serializer = ChangePasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = request.user

    if not user.has_usable_password():
        return Response(
            {"detail": "Password login not enabled for this account"},
            status=400,
        )

    if not user.check_password(
        serializer.validated_data["old_password"]
    ):
        return Response({"detail": "Incorrect password"}, status=400)

    user.set_password(serializer.validated_data["new_password"])
    user.save(update_fields=["password"])

    log_event(
        actor=user,
        action="password.change",
        resource_type="auth",
        request=request,
    )

    return Response({"detail": "Password changed successfully"})