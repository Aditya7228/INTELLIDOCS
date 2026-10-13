from typing import List, Optional
from pydantic import BaseModel, field_validator, ConfigDict

VALID_PERMISSIONS = {"READ", "APPEND", "WRITE"}

class GroupCreateRequest(BaseModel):
    name: str
    member_usernames: Optional[List[str]] = []

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Group name cannot be empty")
        return s

    @field_validator("member_usernames")
    @classmethod
    def validate_member_count(cls, v: Optional[List[str]]) -> List[str]:
        cleaned = [u.strip() for u in (v or []) if u and u.strip()]
        # Group owner is automatically included as a member, so max additional initial members is 6
        if len(cleaned) > 6:
            raise ValueError("Groups can contain up to 7 members.")
        return cleaned


class GroupUpdateRequest(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Group name cannot be empty")
        return s


class GroupMemberAddRequest(BaseModel):
    username_or_email: str

    @field_validator("username_or_email")
    @classmethod
    def validate_target(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Username or email is required")
        return s


class GroupShareRequest(BaseModel):
    document_uuid: str
    permission: str = "READ"

    @field_validator("permission")
    @classmethod
    def validate_permission(cls, v: str) -> str:
        upper_p = v.upper().strip()
        if upper_p not in VALID_PERMISSIONS:
            raise ValueError(f"Invalid permission '{v}'. Must be READ, APPEND, or WRITE.")
        return upper_p


class GroupMemberOut(BaseModel):
    user_id: int
    username: str
    email: str
    role: str
    joined_at: str

    model_config = ConfigDict(from_attributes=True)


class GroupOut(BaseModel):
    id: int
    name: str
    owner_id: int
    owner_username: str
    member_count: int
    members: List[GroupMemberOut]
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)
