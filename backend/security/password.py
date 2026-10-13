from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from backend.config import settings

hasher = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=32,
    salt_len=16
)

class PasswordManager:
    COMMON_WEAK_PASSWORDS = {
        "password", "password1234", "password12345", "12345678",
        "123456789", "1234567890", "qwertyuiop", "admin123", "admin1234", "admin12345",
        "letmein123", "welcome123", "iloveyou123", "monkey1234", "dragon1234"
    }

    @classmethod
    def validate_password(cls, password: str) -> tuple[bool, str]:
        if not password or len(password) < settings.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long"

        pwd_lower = password.lower()
        if pwd_lower in cls.COMMON_WEAK_PASSWORDS:
            return False, "Password is too common or easily guessable"

        if len(set(password)) == 1:
            return False, "Password cannot consist of a single repeated character"

        return True, ""

    @staticmethod
    def hash_password(password: str) -> str:
        return hasher.hash(password)

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        try:
            return hasher.verify(hashed_password, password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        try:
            return hasher.check_needs_rehash(hashed_password)
        except Exception:
            return False

