import json
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime, timezone
from backend.models.suggestion import DocumentSuggestion

class SuggestionRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self,
               document_id: int,
               suggestion_type: str,
               suggested_value: str,
               reason: str,
               confidence: float = 1.0,
               current_value: Optional[str] = None,
               evidence: Optional[dict] = None) -> DocumentSuggestion:
        s = DocumentSuggestion(
            document_id=document_id,
            suggestion_type=suggestion_type,
            current_value=current_value,
            suggested_value=suggested_value,
            reason=reason,
            confidence=confidence,
            evidence=json.dumps(evidence) if evidence else None,
            status="pending",
            created_for_user_id=self.db.info.get("suggestion_scope_user_id")
        )
        self.db.add(s)
        self.db.commit()
        self.db.refresh(s)
        return s

    def get_by_id(self, suggestion_id: int) -> Optional[DocumentSuggestion]:
        return self.db.query(DocumentSuggestion).filter(
            DocumentSuggestion.id == suggestion_id
        ).first()

    def get_for_document(self, document_id: int) -> List[DocumentSuggestion]:
        return self.db.query(DocumentSuggestion).filter(
            DocumentSuggestion.document_id == document_id
        ).order_by(desc(DocumentSuggestion.created_at)).all()

    def get_existing_for_document(self, document_id: int, suggestion_type: str) -> Optional[DocumentSuggestion]:
        scope_user_id = self.db.info.get("suggestion_scope_user_id")
        return self.db.query(DocumentSuggestion).filter(
            DocumentSuggestion.document_id == document_id,
            DocumentSuggestion.suggestion_type == suggestion_type,
            DocumentSuggestion.created_for_user_id == scope_user_id,
        ).order_by(desc(DocumentSuggestion.created_at)).first()

    def list_pending_for_user(self, owner_id: int, document_id: Optional[int] = None) -> List[DocumentSuggestion]:
        """List pending suggestions for documents owned by owner_id."""
        from backend.models.document import DocumentModel
        query = self.db.query(DocumentSuggestion).join(
            DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
        ).filter(
            DocumentModel.owner_id == owner_id,
            DocumentModel.is_deleted == 0,
            DocumentSuggestion.status == "pending",
            DocumentSuggestion.created_for_user_id == self.db.info.get("suggestion_scope_user_id")
        )
        if document_id:
            query = query.filter(DocumentSuggestion.document_id == document_id)
        return query.order_by(desc(DocumentSuggestion.created_at)).all()


    def find_group_suggestion(self, owner_id: int, folder_name: str, document_ids: List[int]) -> Optional[DocumentSuggestion]:
        """Find an existing pending library-level folder suggestion for an owner.

        Library analysis can discover the same category cluster with a changed
        document set as new files arrive. A pending suggestion for the same
        proposed folder should therefore be updated instead of creating another
        pending card. Resolved suggestions are intentionally ignored so a truly
        new context can produce a fresh recommendation.
        """
        from backend.models.document import DocumentModel

        candidates = self.db.query(DocumentSuggestion).join(
            DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
        ).filter(
            DocumentSuggestion.suggestion_type == "create_folder_group",
            DocumentModel.owner_id == owner_id,
            DocumentSuggestion.status == "pending",
            DocumentSuggestion.created_for_user_id == self.db.info.get("suggestion_scope_user_id")
        ).order_by(desc(DocumentSuggestion.created_at)).all()

        normalized_folder = folder_name.strip().lower()
        for suggestion in candidates:
            if suggestion.suggested_value.strip().lower() == normalized_folder:
                return suggestion

        return None

    def resolve(self, suggestion_id: int, status: str, resolved_by: int) -> Optional[DocumentSuggestion]:
        s = self.get_by_id(suggestion_id)
        if s:
            s.status = status
            s.resolved_at = datetime.now(timezone.utc).isoformat()
            s.resolved_by = resolved_by
            self.db.commit()
            self.db.refresh(s)
        return s
