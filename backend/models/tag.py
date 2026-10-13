from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.database.connection import Base

document_tags = Table(
    "document_tags",
    Base.metadata,
    Column("document_id", Integer, ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
    Column("assigned_at", String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat()),
    Column("assigned_by", Integer, ForeignKey("users.id"), nullable=False)
)

class Tag(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False, index=True)
    color = Column(String, nullable=False, default="#6366f1")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    documents = relationship("DocumentModel", secondary=document_tags, back_populates="tags")
