from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken


from .serializers import LoginSerializer, RegisterSerializer
from .models import User, UserSession
from .tokens import verify_email_verification_token, generate_email_verification_token
from .emails import send_verification_email
from .audit import log_event


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
