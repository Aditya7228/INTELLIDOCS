from pydantic import BaseModel, ConfigDict
from typing import Optional

class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    detail: Optional[str] = None
    success: int
    timestamp: str

    model_config = ConfigDict(from_attributes=True)
