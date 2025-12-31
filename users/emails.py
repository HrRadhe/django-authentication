from django.conf import settings
from django.core.mail import send_mail


def send_verification_email(user, token):
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

    send_mail(
        subject="Verify your email",
        message=f"Click the link to verify your email: {verify_url}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )


def send_password_reset_email(email: str, reset_link: str):
    subject = "Reset your password"
    message = (
        "You requested a password reset.\n\n"
        f"Click the link below to reset your password:\n\n"
        f"{reset_link}\n\n"
        "If you did not request this, you can safely ignore this email."
    )

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )