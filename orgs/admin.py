from django.contrib import admin
from .models import Organisation, Membership, Permission, RolePermission


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    autocomplete_fields = ("user",)
    readonly_fields = ("joined_at",)


@admin.register(Organisation)
class OrganisationAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "owner",
        "is_active",
        "created_at",
    )
    list_filter = ("is_active",)
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
    readonly_fields = ("created_at", "updated_at")
    inlines = [MembershipInline]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("owner")
    

@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "organisation",
        "role",
        "is_active",
        "joined_at",
    )
    list_filter = ("role", "is_active")
    search_fields = (
        "user__email",
        "organisation__name",
        "organisation__slug",
    )
    autocomplete_fields = ("user", "organisation")
    readonly_fields = ("joined_at",)

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("user", "organisation")
    

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("code",)
    search_fields = ("code",)


@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ("role", "permission")
    list_filter = ("role",)