from sqlalchemy import Column, Integer, String, ForeignKey
from backend.database.connection import Base


class MFAPendingChallenge(Base):
    __tablename__ = "mfa_pending_challenges"

    challenge_hash = Column(String, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    issued_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False, index=True)
    used = Column(Integer, nullable=False, default=0, index=True)
    used_at = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
