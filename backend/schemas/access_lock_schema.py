from typing import Optional
from pydantic import BaseModel, field_validator

class AccessLockEnableRequest(BaseModel):
    access_key: str
    confirm_access_key: str

    @field_validator("access_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        if len(v) < 4:
            raise ValueError("Access key must be at least 4 characters long")
        return v


class AccessLockUnlockRequest(BaseModel):
    access_key: str


class AccessLockChangeRequest(BaseModel):
    current_key: Optional[str] = None
    new_key: str
    confirm_new_key: str

    @field_validator("new_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        if len(v) < 4:
            raise ValueError("New access key must be at least 4 characters long")
        return v


class AccessLockUnlockResponse(BaseModel):
    lock_token: str
    expires_in: int = 3600
    message: str = "Document unlocked successfully"
