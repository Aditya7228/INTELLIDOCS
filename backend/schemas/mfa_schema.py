from pydantic import BaseModel
from typing import Optional, List

class MFASetupInitiate(BaseModel):
    password: str

class MFASetupInitiateResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_base64: str

class MFASetupConfirm(BaseModel):
    code: str

class MFASetupConfirmResponse(BaseModel):
    is_enabled: bool
    recovery_codes: List[str]

class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str

class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None

class MFARequestWithPassword(BaseModel):
    password: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None

class MFAStatusResponse(BaseModel):
    is_enabled: bool
    has_recovery_codes: bool
    remaining_recovery_codes: int
