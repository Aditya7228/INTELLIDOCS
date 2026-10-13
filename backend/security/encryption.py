import base64
import hashlib
from cryptography.fernet import Fernet
from backend.config import settings

def _get_fernet_key() -> bytes:
    key_bytes = hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(key_bytes)

class SecretCipher:
    @staticmethod
    def encrypt(plaintext: str) -> str:
        if not plaintext:
            return ""
        f = Fernet(_get_fernet_key())
        return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str) -> str:
        if not ciphertext:
            return ""
        f = Fernet(_get_fernet_key())
        return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
