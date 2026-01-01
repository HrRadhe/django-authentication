
from rest_framework.exceptions import PermissionDenied
from .models import UserRolePermission


def require_user_permission(user, permission_code):
    allowed = UserRolePermission.objects.filter(
        role=user.role,
        permission__code=permission_code,
    ).exists()

    if not allowed:
        raise PermissionDenied("Permission denied")