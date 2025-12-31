import json
import base64
from django.core.signing import TimestampSigner, BadSignature, SignatureExpired

signer = TimestampSigner()


def encode_state(data: dict) -> str:
    """
    data example:
    {
        "provider": "google",
        "next": "/dashboard"
    }
    """
    raw = json.dumps(data)
    signed = signer.sign(raw)
    return base64.urlsafe_b64encode(signed.encode()).decode()


def decode_state(state: str, max_age=300):
    """
    max_age: 5 minutes
    """
    try:
        signed = base64.urlsafe_b64decode(state.encode()).decode()
        raw = signer.unsign(signed, max_age=max_age)
        return json.loads(raw)
    except (BadSignature, SignatureExpired, ValueError):
        return None
    

def generate_password_reset_token(user):
    return signer.sign(str(user.id))

def verify_password_reset_token(token, max_age=900):  # 15 min
    try:
        return signer.unsign(token, max_age=max_age)
    except Exception:
        return None