from django.core.management.base import BaseCommand

from orgs.models import Permission, RolePermission, OrgRole
from users.models import (
    UserPermission,
    UserRolePermission,
    UserRole,
)


ORG_PERMISSIONS = {
    OrgRole.OWNER: [
        "org.view",
        "org.update",
        "org.delete",
        "member.invite",
        "member.remove",
        "member.role.change",
    ],
    OrgRole.ADMIN: [
        "org.view",
        "org.update",
        "member.invite",
    ],
    OrgRole.MEMBER: [
        "org.view",
    ],
}

USER_PERMISSIONS = {
    UserRole.SYSTEM_ADMIN: [
        "internal.dashboard.view",
        "internal.users.read",
        "internal.users.write",
        "internal.audit.read",
    ],
    UserRole.DATA_ADMIN: [
        "internal.audit.read",
    ],
    UserRole.STAFF: [
        "internal.dashboard.view",
    ],
    # END_USER intentionally empty
}


class Command(BaseCommand):
    help = "Seed org-level and user-level permissions"

    def handle(self, *args, **options):
        self.stdout.write("Seeding org permissions…")

        for role, perms in ORG_PERMISSIONS.items():
            for code in perms:
                perm, _ = Permission.objects.get_or_create(
                    code=code,
                    defaults={"description": code.replace(".", " ").title()},
                )
                RolePermission.objects.get_or_create(
                    role=role,
                    permission=perm,
                )

        self.stdout.write("Seeding user permissions…")

        for role, perms in USER_PERMISSIONS.items():
            for code in perms:
                perm, _ = UserPermission.objects.get_or_create(
                    code=code,
                    defaults={"description": code.replace(".", " ").title()},
                )
                UserRolePermission.objects.get_or_create(
                    role=role,
                    permission=perm,
                )

        self.stdout.write(self.style.SUCCESS("Permissions seeded successfully"))