from .models import User, UserIdentity, IdentityProvider


def get_or_create_user_from_sso(
    *,
    provider,
    provider_user_id,
    email,
    name,
):
    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "name": name,
            "is_email_verified": True,
        },
    )

    UserIdentity.objects.get_or_create(
        user=user,
        provider=provider,
        provider_user_id=str(provider_user_id),
    )

    return user, created