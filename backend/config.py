import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    SECRET_KEY: str = "intellidocs_default_secret_key_change_in_production_9f8e7d6c5b4a"
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'data' / 'intellidocs.db'}"
    STORAGE_DIR: str = str(BASE_DIR / "storage")
    MAX_UPLOAD_SIZE_MB: int = 50
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536
    ARGON2_PARALLELISM: int = 4
    ENABLE_SEMANTIC_SEARCH: bool = True
    ENABLE_ZERO_SHOT_CLASSIFIER: bool = False
    ENABLE_SUMMARIZER: bool = False
    LOG_LEVEL: str = "INFO"
    ALLOWED_ORIGINS: str = "http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000"

    # Brute-force / rate-limit settings
    LOGIN_MAX_ATTEMPTS: int = 5          # failures before temporary lockout
    LOGIN_LOCKOUT_SECONDS: int = 900     # 15 minutes lockout window
    LOGIN_ATTEMPT_WINDOW_SECONDS: int = 600  # rolling window for counting failures

    # Password policy
    PASSWORD_MIN_LENGTH: int = 10        # minimum password length (overrides schema)

    # Proxy safety settings
    TRUST_PROXY_HEADERS: bool = False    # Set True only when running behind trusted reverse proxy
    TRUSTED_PROXIES: str = "127.0.0.1,::1" # Comma-separated trusted proxy IP list


    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
