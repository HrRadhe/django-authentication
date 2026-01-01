from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserSession, AuditLog, UserIdentity, UserPermission, UserRolePermission




@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ("email",)

    list_display = (
        "email",
        "name",
        "role",
        "is_active",
        "is_email_verified",
        "created_at",
    )

    list_filter = (
        "role",
        "is_active",
        "is_email_verified",
    )

    search_fields = ("email", "name")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("name",)}),
        (
            "Access Control",
            {
                "fields": (
                    "role",
                    "is_active",
                    "is_email_verified",
                )
            },
        ),
        ("Timestamps", {"fields": ("last_login",)}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "name",
                    "role",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    readonly_fields = ("last_login",)


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
    

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "actor",
        "action",
        "resource_type",
        "resource_id",
        "ip_address",
    )

    list_filter = ("action", "resource_type", "created_at")
    search_fields = ("actor__email", "resource_id")

    readonly_fields = (
        "actor",
        "action",
        "resource_type",
        "resource_id",
        "metadata",
        "ip_address",
        "user_agent",
        "created_at",
    )

    ordering = ("-created_at",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
    

@admin.register(UserIdentity)
class UserIdentityAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "provider",
        "provider_user_id",
        "created_at",
    )

    list_filter = ("provider",)
    search_fields = ("user__email", "provider_user_id")

    readonly_fields = (
        "user",
        "provider",
        "provider_user_id",
        "created_at",
    )

    ordering = ("-created_at",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
    

@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ("code",)
    search_fields = ("code",)


@admin.register(UserRolePermission)
class UserRolePermissionAdmin(admin.ModelAdmin):
    list_display = ("role", "permission")
    list_filter = ("role",)