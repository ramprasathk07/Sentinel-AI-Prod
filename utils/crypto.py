import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# We use a master key from environment or a derived one.
# If SENTINEL_ENCRYPTION_KEY is not set, we use a fallback (less secure).
SECRET = os.getenv("SENTINEL_ENCRYPTION_KEY", "sentinel-ai-default-unsafe-key-32chars!!")

def _get_fernet():
    # Derive a 32-byte key from the secret
    salt = b'sentinel_salt_v1'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(SECRET.encode()))
    return Fernet(key)

def encrypt_token(token: str) -> str:
    """Encrypt a GitHub token for storage."""
    if not token:
        return ""
    f = _get_fernet()
    return f.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt a GitHub token for use."""
    if not encrypted_token:
        return ""
    f = _get_fernet()
    try:
        return f.decrypt(encrypted_token.encode()).decode()
    except Exception:
        return ""
