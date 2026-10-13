from sqlalchemy import Column, Integer, String, ForeignKey, Index
from backend.database.connection import Base


class PasswordResetToken(Base):
    """Hash-only, expiring, single-use password reset token."""
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(String, nullable=False, index=True)
    expires_at = Column(String, nullable=False)
    used_at = Column(String, nullable=True)
    requested_ip = Column(String, nullable=True)

    __table_args__ = (
        Index("ix_password_reset_tokens_user_created", "user_id", "created_at"),
    )
