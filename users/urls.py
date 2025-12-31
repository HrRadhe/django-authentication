from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path("auth/register/", views.register_view, name="register"),
    path("auth/login/", views.login_view, name="login"),
    path("auth/logout/", views.logout_view, name="logout"),
    path("auth/token/refresh/", views.token_refresh_view, name="token_refresh"),

    # User
    path("users/me/", views.me_view, name="me"),
    path("users/verify-email/", views.verify_email_view, name="verify_email"),
    path("users/resend-verification/", views.resend_verification_view, name="resend_verification"),
]