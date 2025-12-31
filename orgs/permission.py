from rest_framework.exceptions import PermissionDenied
from .models import RolePermission


def require_permission(membership, permission_code):
    allowed = RolePermission.objects.filter(
        role=membership.role,
        permission__code=permission_code,
    ).exists()

    if not allowed:
        raise PermissionDenied("Permission denied")