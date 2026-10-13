from pydantic import BaseModel
from typing import Optional

class SessionOut(BaseModel):
    jti: str
    issued_at: str
    expires_at: str
    ip_address: Optional[str] = None
    is_current: bool = False

class NotificationSettingsOut(BaseModel):
    email_notifications: bool
    in_app_notifications: bool
    suggestion_alerts: bool
    duplicate_alerts: bool
    security_alerts: bool

class NotificationSettingsUpdate(BaseModel):
    email_notifications: Optional[bool] = None
    in_app_notifications: Optional[bool] = None
    suggestion_alerts: Optional[bool] = None
    duplicate_alerts: Optional[bool] = None
    security_alerts: Optional[bool] = None
