import hmac
import hashlib
import secrets

from backend.config import settings


class ShareKeyService:
    """Recipient-bound document share-key generation and verification."""

    PREFIX = "intellidocs-share-key:v1"

    @staticmethod
    def _secret() -> bytes:
        secret = str(getattr(settings, "SECRET_KEY", "") or "")
        if len(secret) < 16:
            raise RuntimeError("SECRET_KEY is not configured strongly enough")
        return secret.encode("utf-8")

    @classmethod
    def generate_key(cls) -> str:
        return secrets.token_urlsafe(24)

    @classmethod
    def _message(cls, share_id: int, recipient_user_id: int, raw_key: str) -> bytes:
        return f"{cls.PREFIX}:{int(share_id)}:{int(recipient_user_id)}:{raw_key}".encode("utf-8")

    @classmethod
    def hash_key(cls, share_id: int, recipient_user_id: int, raw_key: str) -> str:
        return hmac.new(cls._secret(), cls._message(share_id, recipient_user_id, raw_key), hashlib.sha256).hexdigest()

    @classmethod
    def verify_key(cls, share_id: int, recipient_user_id: int, raw_key: str, stored_hash: str) -> bool:
        if not stored_hash or not raw_key:
            return False
        candidate = cls.hash_key(share_id, recipient_user_id, raw_key)
        return hmac.compare_digest(candidate, stored_hash)
