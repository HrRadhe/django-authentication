from rest_framework.exceptions import PermissionDenied
from .models import Membership, OrgRole


def get_membership(user, organisation):
    try:
        return Membership.objects.get(
            user=user,
            organisation=organisation,
            is_active=True,
        )
    except Membership.DoesNotExist:
        raise PermissionDenied("Not a member of this organisation")


def require_role(membership, allowed_roles):
    if membership.role not in allowed_roles:
        raise PermissionDenied("Insufficient permissions")