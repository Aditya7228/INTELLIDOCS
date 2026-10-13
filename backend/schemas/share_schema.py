from typing import List, Optional
from pydantic import BaseModel, field_validator, ConfigDict

VALID_PERMISSIONS = {"READ", "APPEND", "WRITE"}

class UserSearchOut(BaseModel):
    id: int
    username: str
    email: str

    model_config = ConfigDict(from_attributes=True)


class ShareCreateRequest(BaseModel):
    target_users: List[str]  # List of usernames or emails (max 5 per share action)
    permission: str = "READ"
    protect_with_key: bool = False

    @field_validator("target_users")
    @classmethod
    def validate_recipients_limit(cls, v: List[str]) -> List[str]:
        cleaned = []
        seen = set()
        for u in v:
            if u and u.strip():
                val = u.strip()
                key = val.lower()
                if key not in seen:
                    seen.add(key)
                    cleaned.append(val)
        if not cleaned:
            raise ValueError("At least one recipient username or email is required")
        if len(cleaned) > 5:
            raise ValueError("You can share with up to 5 people at a time.")
        return cleaned

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        upper_p = v.upper().strip()
        if upper_p not in VALID_PERMISSIONS:
            raise ValueError(f"Invalid permission '{v}'. Must be READ, APPEND, or WRITE.")
        return upper_p


class ShareUpdatePermissionRequest(BaseModel):
    permission: str

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        upper_p = v.upper().strip()
        if upper_p not in VALID_PERMISSIONS:
            raise ValueError(f"Invalid permission '{v}'. Must be READ, APPEND, or WRITE.")
        return upper_p


class ShareOut(BaseModel):
    id: int
    document_id: int
    document_uuid: str
    document_name: str
    owner_id: int
    owner_username: str
    target_user_id: int
    target_username: str
    target_email: str
    permission: str
    source: str = "direct"  # direct, group
    group_name: Optional[str] = None
    # Stable group identity matters when a user has multiple groups with the same name.
    group_id: Optional[int] = None
    created_at: str
    updated_at: str
    revoked_at: Optional[str] = None
    active: bool
    share_key_required: bool = False
    share_key_verified: bool = True
    share_key: Optional[str] = None
    share_key_created_at: Optional[str] = None
    share_key_rotated_at: Optional[str] = None
    # Safe, recipient-visible summary only; never include raw findings/PII here.
    access_locked: Optional[bool] = None
    security_status: Optional[str] = None
    security_verdict: Optional[str] = None
    security_risk_level: Optional[str] = None
    security_scanner_status: Optional[str] = None
    security_confidence: Optional[str] = None
    security_assessed_at: Optional[str] = None
    # False until this recipient has reviewed the current linked assessment and activated access.
    access_activated: bool = False

    model_config = ConfigDict(from_attributes=True)


class ShareActivationRequest(BaseModel):
    assessment_id: int
    acknowledge_limited: bool = False


class ShareKeyVerifyRequest(BaseModel):
    key: str


class ShareKeyStatusOut(BaseModel):
    share_id: int
    required: bool
    verified: bool
    created_at: Optional[str] = None
    rotated_at: Optional[str] = None
