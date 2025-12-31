from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView


from .serializers import LoginSerializer, RegisterSerializer
from .models import User
from .tokens import verify_email_verification_token, generate_email_verification_token
from .emails import send_verification_email



@api_view(["POST"])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.save()

    token = generate_email_verification_token(user)
    send_verification_email(user, token)

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
    # Stateless JWT: client deletes token
    return Response({"detail": "Logged out"}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def token_refresh_view(request):
    view = TokenRefreshView.as_view()
    return view(request._request)


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
