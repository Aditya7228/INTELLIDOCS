from sqlalchemy import Column, Integer, String, Float, ForeignKey, UniqueConstraint
from datetime import datetime, timezone
from backend.database.connection import Base

class DocumentRelation(Base):
    __tablename__ = "document_relations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    doc_a_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    doc_b_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    relation_type = Column(String, nullable=False, index=True) # duplicate, near_duplicate, version, related
    similarity_score = Column(Float, nullable=False)
    detected_by = Column(String, nullable=False) # sha256, lsh, embedding, user
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    __table_args__ = (
        UniqueConstraint("doc_a_id", "doc_b_id", name="uq_doc_relation_pair"),
    )

class DocumentVersion(Base):
    __tablename__ = "document_versions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    parent_id = Column(Integer, ForeignKey("document_versions.id"), nullable=True, index=True)
    change_summary = Column(String, nullable=True)
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_doc_version"),
    )
