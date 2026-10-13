from sqlalchemy import Column, Integer, String, Float, ForeignKey
from datetime import datetime, timezone
import json
from backend.database.connection import Base

class DocumentSuggestion(Base):
    __tablename__ = "document_suggestions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    # NULL means an owner/global suggestion. A non-NULL value is a personal suggestion
    # for an activated recipient; it must never be shown to other users.
    created_for_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    suggestion_type = Column(String, nullable=False, index=True)  # rename, categorize, move_folder, add_tag
    current_value = Column(String, nullable=True)
    suggested_value = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    evidence = Column(String, nullable=True)  # JSON blob of supporting signals
    status = Column(String, nullable=False, default="pending", index=True)  # pending, accepted, edited, rejected
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    resolved_at = Column(String, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    @property
    def evidence_dict(self):
        if not self.evidence:
            return {}
        try:
            return json.loads(self.evidence) if isinstance(self.evidence, str) else self.evidence
        except (TypeError, ValueError):
            return {"raw": str(self.evidence)}
