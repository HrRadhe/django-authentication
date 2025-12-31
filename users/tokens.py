from django.core.signing import TimestampSigner, BadSignature, SignatureExpired

signer = TimestampSigner()


def generate_email_verification_token(user):
    return signer.sign(str(user.id))


def verify_email_verification_token(token, max_age=60 * 60 * 24):
    """
    max_age: 24 hours by default
    """
    try:
        user_id = signer.unsign(token, max_age=max_age)
        return user_id
    except (BadSignature, SignatureExpired):
        return None