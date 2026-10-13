from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from datetime import datetime, timezone
from backend.models.document import DocumentModel
from backend.models.document_relation import DocumentRelation

class DocumentRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, doc_data: dict) -> DocumentModel:
        doc = DocumentModel(**doc_data)
        self.db.add(doc)
        self.db.commit()
        self.db.refresh(doc)
        return doc

    def get_by_uuid(self, uuid: str) -> Optional[DocumentModel]:
        return self.db.query(DocumentModel).filter(
            DocumentModel.uuid == uuid,
            DocumentModel.is_deleted == 0
        ).first()

    def get_by_id(self, doc_id: int) -> Optional[DocumentModel]:
        return self.db.query(DocumentModel).filter(
            DocumentModel.id == doc_id,
            DocumentModel.is_deleted == 0
        ).first()

    def get_by_sha256(self, sha256_hash: str) -> List[DocumentModel]:
        return self.db.query(DocumentModel).filter(
            DocumentModel.sha256_hash == sha256_hash,
            DocumentModel.is_deleted == 0
        ).all()

    def list_user_documents(
        self,
        owner_id: int,
        page: int = 1,
        limit: int = 20,
        file_type: Optional[str] = None,
        category: Optional[str] = None,
        sensitivity: Optional[str] = None,
        tag_id: Optional[int] = None,
        sort_by: str = "uploaded_at",
        order: str = "desc"
    ) -> Tuple[List[DocumentModel], int]:
        query = self.db.query(DocumentModel).filter(
            DocumentModel.owner_id == owner_id,
            DocumentModel.is_deleted == 0
        )

        if file_type:
            query = query.filter(DocumentModel.file_type == file_type)
        if category:
            query = query.filter(DocumentModel.category == category)
        if sensitivity:
            query = query.filter(DocumentModel.sensitivity == sensitivity)
        if tag_id:
            query = query.filter(DocumentModel.tags.any(id=tag_id))

        total = query.count()

        # Sorting
        sort_col = getattr(DocumentModel, sort_by, DocumentModel.uploaded_at)
        if order.lower() == "desc":
            query = query.order_by(desc(sort_col))
        else:
            query = query.order_by(asc(sort_col))

        offset = (page - 1) * limit
        items = query.offset(offset).limit(limit).all()
        return items, total

    def update_processing_results(
        self,
        doc_id: int,
        extracted_text: str,
        page_count: int,
        word_count: int,
        language: str,
        category: str,
        category_source: str,
        sensitivity: str,
        has_ocr: int,
        ocr_confidence: Optional[float],
        has_embedded_js: int,
        status: str = "done",
        error: Optional[str] = None
    ):
        doc = self.get_by_id(doc_id)
        if doc:
            doc.extracted_text = extracted_text
            doc.page_count = page_count
            doc.word_count = word_count
            doc.language = language
            doc.category = category
            doc.category_source = category_source
            doc.sensitivity = sensitivity
            doc.has_ocr = has_ocr
            doc.ocr_confidence = ocr_confidence
            doc.has_embedded_js = has_embedded_js
            doc.processing_status = status
            doc.processing_error = error
            doc.processed_at = datetime.now(timezone.utc).isoformat()
            self.db.commit()

    def update(self, doc_id: int, updates: dict) -> Optional[DocumentModel]:
        doc = self.get_by_id(doc_id)
        if doc:
            for k, v in updates.items():
                if v is not None and hasattr(doc, k):
                    setattr(doc, k, v)
            self.db.commit()
            self.db.refresh(doc)
        return doc

    def soft_delete(self, doc_id: int, user_id: int):
        doc = self.get_by_id(doc_id)
        if doc:
            doc.is_deleted = 1
            doc.deleted_at = datetime.now(timezone.utc).isoformat()
            doc.deleted_by = user_id
            self.db.commit()

    def create_relation(self, doc_a_id: int, doc_b_id: int, relation_type: str, score: float, detected_by: str):
        # Ensure ordered pair to respect unique constraint
        a, b = min(doc_a_id, doc_b_id), max(doc_a_id, doc_b_id)
        existing = self.db.query(DocumentRelation).filter(
            DocumentRelation.doc_a_id == a,
            DocumentRelation.doc_b_id == b
        ).first()

        if not existing:
            rel = DocumentRelation(
                doc_a_id=a,
                doc_b_id=b,
                relation_type=relation_type,
                similarity_score=score,
                detected_by=detected_by
            )
            self.db.add(rel)
            self.db.commit()

    def upsert_duplicate_relation(self, doc_a_id: int, doc_b_id: int, relation_type: str, score: float, detected_by: str):
        """Create/refresh a system duplicate relation without overwriting other relation kinds."""
        duplicate_types = {
            "duplicate", "content_duplicate", "exact_duplicate",
            "near_duplicate", "visual_similarity",
        }
        a, b = min(doc_a_id, doc_b_id), max(doc_a_id, doc_b_id)
        existing = self.db.query(DocumentRelation).filter(
            DocumentRelation.doc_a_id == a,
            DocumentRelation.doc_b_id == b,
        ).first()

        if existing:
            existing_type = (existing.relation_type or "").strip().lower()
            provenance = (existing.detected_by or "").strip().lower()
            provenance_tokens = {
                token.strip().replace("_", "-")
                for token in provenance.replace(";", ",").split(",")
            }
            if provenance_tokens.intersection({"user", "manual", "user-created", "user created"}):
                return None
            if existing_type not in duplicate_types and existing_type != "stale_duplicate":
                # Unique pair constraint: retain version/related/semantic/unknown edges.
                # The caller may still return fresh duplicate evidence in the API;
                # this repository method must not destroy the existing edge.
                return None
            existing.relation_type = relation_type
            existing.similarity_score = float(score)
            existing.detected_by = detected_by or "system"
        else:
            existing = DocumentRelation(
                doc_a_id=a,
                doc_b_id=b,
                relation_type=relation_type,
                similarity_score=float(score),
                detected_by=detected_by or "system",
            )
            self.db.add(existing)

        self.db.commit()
        self.db.refresh(existing)
        return existing

    def mark_duplicate_relation_stale(self, doc_a_id: int, doc_b_id: int) -> bool:
        """Mark obsolete system duplicate state as stale; never delete the row."""
        duplicate_types = {
            "duplicate", "content_duplicate", "exact_duplicate",
            "near_duplicate", "visual_similarity",
        }
        a, b = min(doc_a_id, doc_b_id), max(doc_a_id, doc_b_id)
        existing = self.db.query(DocumentRelation).filter(
            DocumentRelation.doc_a_id == a,
            DocumentRelation.doc_b_id == b,
        ).first()
        if not existing:
            return False

        existing_type = (existing.relation_type or "").strip().lower()
        provenance = (existing.detected_by or "").strip().lower()
        provenance_tokens = {
            token.strip().replace("_", "-")
            for token in provenance.replace(";", ",").split(",")
        }
        if existing_type not in duplicate_types:
            return False
        if provenance_tokens.intersection({"user", "manual", "user-created", "user created"}):
            return False

        existing.relation_type = "stale_duplicate"
        self.db.commit()
        return True
    def get_relations_for_doc(self, doc_id: int) -> List[Tuple[DocumentModel, str, float, str]]:
        relations = self.db.query(DocumentRelation).filter(
            (DocumentRelation.doc_a_id == doc_id) | (DocumentRelation.doc_b_id == doc_id)
        ).all()

        results = []
        for r in relations:
            other_id = r.doc_b_id if r.doc_a_id == doc_id else r.doc_a_id
            other_doc = self.get_by_id(other_id)
            if other_doc:
                results.append((other_doc, r.relation_type, r.similarity_score, r.detected_by))
        return results
