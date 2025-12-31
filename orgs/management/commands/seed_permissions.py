from django.core.management.base import BaseCommand
from orgs.models import Permission, RolePermission, OrgRole

DEFAULTS = {
    OrgRole.OWNER: [
        "org.view", "org.update", "org.delete",
        "member.invite", "member.remove", "member.role.change",
    ],
    OrgRole.ADMIN: [
        "org.view", "org.update",
        "member.invite",
    ],
    OrgRole.MEMBER: [
        "org.view",
    ],
}

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        for role, perms in DEFAULTS.items():
            for code in perms:
                perm, _ = Permission.objects.get_or_create(code=code)
                RolePermission.objects.get_or_create(
                    role=role,
                    permission=perm,
                )
        self.stdout.write("Permissions seeded")