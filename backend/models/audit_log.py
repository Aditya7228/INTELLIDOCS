from sqlalchemy import Column, Integer, String, ForeignKey
from datetime import datetime, timezone
from backend.database.connection import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    detail = Column(String, nullable=True) # JSON blob string
    success = Column(Integer, nullable=False, default=1)
    timestamp = Column(String, nullable=False, index=True, default=lambda: datetime.now(timezone.utc).isoformat())
