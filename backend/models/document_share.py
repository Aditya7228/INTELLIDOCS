from sqlalchemy import Column, Integer, String, ForeignKey
from datetime import datetime, timezone
from backend.database.connection import Base

class DocumentShare(Base):
    __tablename__ = "document_shares"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = Column(String, nullable=False, default="READ", index=True)  # READ, APPEND, WRITE
    active = Column(Integer, nullable=False, default=1, index=True)  # 1 active, 0 revoked
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    revoked_at = Column(String, nullable=True)

    # Recipient-bound Share Key protection
    share_key_hash = Column(String, nullable=True)
    share_key_required = Column(Integer, nullable=False, default=0)
    share_key_verified_at = Column(String, nullable=True)
    share_key_created_at = Column(String, nullable=True)
    share_key_rotated_at = Column(String, nullable=True)
