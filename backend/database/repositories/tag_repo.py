from datetime import datetime, timezone
from typing import Optional, List, Tuple, Set
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.models.tag import Tag, document_tags
from backend.models.document import DocumentModel

class TagRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, name: str, color: str = "#6366f1", created_by: Optional[int] = None) -> Tag:
        tag = Tag(name=name.strip(), color=color, created_by=created_by)
        self.db.add(tag)
        self.db.commit()
        self.db.refresh(tag)
        return tag

    def get_by_name(self, name: str) -> Optional[Tag]:
        return self.db.query(Tag).filter(Tag.name == name.strip()).first()

    def get_by_id(self, tag_id: int) -> Optional[Tag]:
        return self.db.query(Tag).filter(Tag.id == tag_id).first()

    def list_all(self, document_ids: Optional[Set[int]] = None) -> List[Tuple[Tag, int]]:
        """Return tags with counts limited to accessible, non-deleted documents."""
        tags = self.db.query(Tag).all()
        result = []

        for t in tags:
            if document_ids is not None and not document_ids:
                count = 0
            else:
                query = (
                    self.db.query(document_tags)
                    .join(
                        DocumentModel,
                        DocumentModel.id == document_tags.c.document_id
                    )
                    .filter(
                        document_tags.c.tag_id == t.id,
                        DocumentModel.is_deleted == 0
                    )
                )

                if document_ids is not None:
                    query = query.filter(DocumentModel.id.in_(document_ids))

                count = query.count()

            result.append((t, count))

        return result

    def assign_tags_to_doc(self, doc_id: int, tag_ids: List[int], user_id: int):
        doc = self.db.query(DocumentModel).filter(DocumentModel.id == doc_id).first()
        if not doc:
            return
        existing_rows = self.db.query(document_tags.c.tag_id).filter(document_tags.c.document_id == doc_id).all()
        existing_ids = {r[0] for r in existing_rows}
        now_str = datetime.now(timezone.utc).isoformat()
        for tag_id in tag_ids:
            if tag_id not in existing_ids:
                stmt = document_tags.insert().values(
                    document_id=doc_id,
                    tag_id=tag_id,
                    assigned_at=now_str,
                    assigned_by=user_id
                )
                self.db.execute(stmt)
        self.db.commit()

    def update_owned(self, tag_id: int, user_id: int, name: Optional[str] = None, color: Optional[str] = None) -> Optional[Tag]:
        tag = self.db.query(Tag).filter(Tag.id == tag_id, Tag.created_by == user_id).first()
        if not tag:
            return None
        if name is not None:
            tag.name = name.strip()
        if color is not None:
            tag.color = color
        self.db.commit()
        self.db.refresh(tag)
        return tag

    def delete_owned(self, tag_id: int, user_id: int) -> bool:
        tag = self.db.query(Tag).filter(Tag.id == tag_id, Tag.created_by == user_id).first()
        if not tag:
            return False

        # A globally shared tag cannot be deleted if another user's document uses it.
        used_elsewhere = (
            self.db.query(document_tags.c.document_id)
            .join(DocumentModel, DocumentModel.id == document_tags.c.document_id)
            .filter(document_tags.c.tag_id == tag_id, DocumentModel.owner_id != user_id)
            .first()
        )
        if used_elsewhere:
            return False

        self.db.query(document_tags).filter(document_tags.c.tag_id == tag_id).delete(synchronize_session=False)
        self.db.delete(tag)
        self.db.commit()
        return True

    def remove_tag_from_doc(self, doc_id: int, tag_id: int):
        doc = self.db.query(DocumentModel).filter(DocumentModel.id == doc_id).first()
        if doc:
            doc.tags = [t for t in doc.tags if t.id != tag_id]
            self.db.commit()
