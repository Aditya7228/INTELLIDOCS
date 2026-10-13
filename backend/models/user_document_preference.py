from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from backend.database.connection import Base


class UserDocumentPreference(Base):
    """Per-user presentation/filing preferences for a document shared by another owner.

    Never use this table to change the owner's canonical DocumentModel fields.
    """
    __tablename__ = "user_document_preferences"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    display_name = Column(String, nullable=True)
    category = Column(String, nullable=True)
    folder_id = Column(Integer, ForeignKey("folders.id", ondelete="SET NULL"), nullable=True, index=True)
    updated_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    __table_args__ = (UniqueConstraint("user_id", "document_id", name="uq_user_document_preference"),)
