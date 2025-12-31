from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserSession


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ("email",)
    list_display = ("email", "name", "is_active", "is_email_verified", "created_at")
    search_fields = ("email", "name")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("name",)}),
        ("Status", {"fields": ("is_active", "is_email_verified", "is_staff", "is_superuser")}),
        ("Permissions", {"fields": ("groups", "user_permissions")}),
        ("Timestamps", {"fields": ("last_login",)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "name", "password1", "password2"),
            },
        ),
    )

    filter_horizontal = ("groups", "user_permissions")


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "short_jti",
        "ip_address",
        "is_active",
        "created_at",
        "last_used_at",
    )

    list_filter = ("is_active", "created_at")
    search_fields = ("user__email", "refresh_token_jti")
    readonly_fields = (
        "user",
        "refresh_token_jti",
        "ip_address",
        "user_agent",
        "created_at",
        "last_used_at",
    )

    ordering = ("-last_used_at",)

    def short_jti(self, obj):
        return obj.refresh_token_jti[:8]

    short_jti.short_description = "Session ID"

    def has_add_permission(self, request):
        # Sessions should never be created manually
        return False

    def has_change_permission(self, request, obj=None):
        # Prevent editing session details
        return False