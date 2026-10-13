import jwt
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from backend.config import settings

ALGORITHM = "HS256"

class JWTHandler:
    @staticmethod
    def create_access_token(user_id: int, role: str) -> tuple[str, str]:
        jti = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        payload = {
            "sub": str(user_id),
            "role": role,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp())
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
        return token, jti

    @staticmethod
    def create_refresh_token() -> tuple[str, str]:
        raw_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        return raw_token, token_hash

    @staticmethod
    def hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def create_mfa_token(user_id: int) -> str:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=5)
        jti = secrets.token_hex(16)
        payload = {
            "sub": str(user_id),
            "type": "mfa_pending",
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp())
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode_access_token(token: str) -> dict:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except jwt.PyJWTError:
            return None

    @staticmethod
    def create_access_lock_token(
        doc_uuid: str,
        user_id: int,
        lock_hash: str | None = None,
        expire_hours: int = 1
    ) -> str:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=expire_hours)

        # Bind the unlock token to the current stored password hash.
        # The plaintext access key is never placed in the JWT.
        lock_fingerprint = (
            hashlib.sha256(lock_hash.encode("utf-8")).hexdigest()
            if lock_hash else None
        )

        payload = {
            "sub": str(user_id),
            "doc_uuid": doc_uuid,
            "type": "access_lock_unlocked",
            "lock_fp": lock_fingerprint,
            "iat": int(now.timestamp()),
            "exp": int(expires.timestamp())
        }
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def verify_access_lock_token(
        token: str,
        doc_uuid: str,
        user_id: int,
        current_lock_hash: str | None
    ) -> bool:
        if not token or not current_lock_hash:
            return False

        payload = JWTHandler.decode_access_token(token)
        if not payload:
            return False
        if payload.get("type") != "access_lock_unlocked":
            return False
        if payload.get("doc_uuid") != doc_uuid:
            return False
        if payload.get("sub") != str(user_id):
            return False

        expected_fp = hashlib.sha256(
            current_lock_hash.encode("utf-8")
        ).hexdigest()

        # Tokens created before this patch fail closed when the lock is enabled.
        if payload.get("lock_fp") != expected_fp:
            return False

        return True
