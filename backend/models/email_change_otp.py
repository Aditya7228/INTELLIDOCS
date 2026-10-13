from sqlalchemy import Column, Integer, String, ForeignKey, Index
from backend.database.connection import Base


class EmailChangeOTP(Base):
    """Single-use, expiring OTP records for authenticated email changes."""
    __tablename__ = "email_change_otps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_email = Column(String, nullable=False, index=True)
    otp_digest = Column(String(64), nullable=False)
    created_at = Column(String, nullable=False, index=True)
    expires_at = Column(String, nullable=False)
    used_at = Column(String, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_email_change_user_created", "user_id", "created_at"),
    )
