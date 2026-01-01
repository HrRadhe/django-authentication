from rest_framework.throttling import SimpleRateThrottle


class LoginThrottle(SimpleRateThrottle):
    scope = "login"

    def get_cache_key(self, request, view):
        # IP-based
        ip = self.get_ident(request)
        return f"login:{ip}"


class PasswordResetThrottle(SimpleRateThrottle):
    scope = "password_reset"

    def get_cache_key(self, request, view):
        # Email-based + IP fallback
        email = request.data.get("email")
        if email:
            return f"pwd-reset:{email.lower()}"
        return f"pwd-reset:{self.get_ident(request)}"


class SSOThrottle(SimpleRateThrottle):
    scope = "sso"

    def get_cache_key(self, request, view):
        return f"sso:{self.get_ident(request)}"


class OrgInviteThrottle(SimpleRateThrottle):
    scope = "org_invite"

    def get_cache_key(self, request, view):
        return f"org-invite:{request.user.id}"