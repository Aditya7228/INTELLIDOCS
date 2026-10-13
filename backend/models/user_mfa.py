from sqlalchemy import Column, Integer, String, ForeignKey
from datetime import datetime, timezone
from backend.database.connection import Base

class UserMFA(Base):
    __tablename__ = "user_mfa"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    secret_encrypted = Column(String, nullable=True)
    is_enabled = Column(Integer, nullable=False, default=0)
    recovery_codes_hash = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at = Column(String, nullable=True)
