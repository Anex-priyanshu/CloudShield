"""Credential encryption/decryption using Fernet."""
import json
from cryptography.fernet import Fernet
import base64

from app.config import settings


def _get_fernet() -> Fernet:
    key = settings.fernet_key
    # Ensure key is proper Fernet key format
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        # Generate a valid key if the stored one is malformed
        valid_key = base64.urlsafe_b64encode(key.encode()[:32].ljust(32, b'0'))
        return Fernet(valid_key)


def encrypt_credentials(data: dict) -> str:
    f = _get_fernet()
    return f.encrypt(json.dumps(data).encode()).decode()


def decrypt_credentials(ciphertext: str) -> dict:
    f = _get_fernet()
    return json.loads(f.decrypt(ciphertext.encode()).decode())
