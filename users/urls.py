from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path("auth/register/", views.register_view, name="register"),
    path("auth/login/", views.login_view, name="login"),
    path("auth/logout/", views.logout_view, name="logout"),
    path("auth/logout-all/", views.logout_all_view),
    path("auth/token/refresh/", views.token_refresh_view, name="token_refresh"),

    # SSO
    path("auth/sso/callback/", views.sso_callback_view),
    path("auth/sso/<str:provider>/", views.sso_login_view),

    # Passwords
    path("auth/set-password/", views.set_password_view),
    path("auth/forgot-password/", views.forgot_password_view),
    path("auth/reset-password/", views.reset_password_view),
    path("auth/change-password/", views.change_password_view),

    # User
    path("users/me/", views.me_view, name="me"),
    path("users/verify-email/", views.verify_email_view, name="verify_email"),
    path("users/resend-verification/", views.resend_verification_view, name="resend_verification"),

    # Test User Permissions
    path("internal/dashboard/", views.internal_dashboard_view),
    path("internal/users/", views.internal_users_list_view),
    path("internal/audit-logs/", views.internal_audit_logs_view),
]