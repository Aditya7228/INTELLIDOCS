from sqlalchemy import Column, Integer, String, ForeignKey
from backend.database.connection import Base

class Session(Base):
    __tablename__ = "sessions"

    jti = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, unique=True, nullable=False)
    issued_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    revoked = Column(Integer, nullable=False, default=0)
    revoked_at = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
