from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint, Index
from backend.database.connection import Base


class ShareAccessActivation(Base):
    """Recipient-specific acceptance of a direct or group document share.

    A single group-share row can have many independent recipients, so activation
    is stored per (source_type, share_id, user_id), not on the group share itself.
    The assessment_id binds activation to the exact assessment reviewed by the
    recipient. A newer assessment automatically requires a fresh review.
    """
    __tablename__ = "share_access_activations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    source_type = Column(String, nullable=False, index=True)  # direct | group
    share_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_id = Column(Integer, ForeignKey("security_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    activated_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    limited_checks_acknowledged = Column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint("source_type", "share_id", "user_id", name="uq_share_access_activation_recipient"),
        Index("ix_share_access_activation_source_recipient", "source_type", "share_id", "user_id"),
    )
