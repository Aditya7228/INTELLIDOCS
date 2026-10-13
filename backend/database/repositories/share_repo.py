from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.models.document_share import DocumentShare
from backend.models.group import GroupDocumentShare
from backend.models.user import User
from backend.models.document import DocumentModel

class ShareRepository:
    def __init__(self, db: Session):
        self.db = db

    def _invalidate_activation(self, source_type: str, share_id: int):
        # A re-share, permission change, or Share Key rotation requires fresh
        # recipient review. Delete only the matching grant's acceptance records.
        from backend.models.share_access_activation import ShareAccessActivation
        self.db.query(ShareAccessActivation).filter(
            ShareAccessActivation.source_type == source_type,
            ShareAccessActivation.share_id == share_id,
        ).delete(synchronize_session=False)

    def create_direct_share(
        self,
        document_id: int,
        owner_id: int,
        target_user_id: int,
        permission: str = "READ",
        share_key_required: int = 0,
    ) -> DocumentShare:
        existing = self.db.query(DocumentShare).filter(
            DocumentShare.document_id == document_id,
            DocumentShare.target_user_id == target_user_id
        ).first()

        now = datetime.now(timezone.utc).isoformat()

        if existing:
            self._invalidate_activation("direct", existing.id)
            existing.owner_id = owner_id
            existing.permission = permission
            existing.active = 1
            existing.revoked_at = None
            existing.updated_at = now
            existing.share_key_required = int(bool(share_key_required))
            existing.share_key_verified_at = None
            if not share_key_required:
                existing.share_key_hash = None
                existing.share_key_created_at = None
                existing.share_key_rotated_at = None
            self.db.commit()
            self.db.refresh(existing)
            return existing

        share = DocumentShare(
            document_id=document_id,
            owner_id=owner_id,
            target_user_id=target_user_id,
            permission=permission,
            active=1,
            created_at=now,
            updated_at=now,
            share_key_required=int(bool(share_key_required)),
        )
        self.db.add(share)
        self.db.commit()
        self.db.refresh(share)
        return share

    def get_direct_share_by_id(self, share_id: int) -> Optional[DocumentShare]:
        return self.db.query(DocumentShare).filter(DocumentShare.id == share_id).first()

    def set_share_key(self, share_id: int, key_hash: str, created_at: Optional[str] = None, rotated_at: Optional[str] = None) -> Optional[DocumentShare]:
        share = self.get_direct_share_by_id(share_id)
        if not share or share.active != 1:
            return None
        self._invalidate_activation("direct", share.id)
        now = datetime.now(timezone.utc).isoformat()
        share.share_key_hash = key_hash
        share.share_key_required = 1
        share.share_key_verified_at = None
        share.share_key_created_at = created_at or now
        share.share_key_rotated_at = rotated_at
        share.updated_at = now
        self.db.commit()
        self.db.refresh(share)
        return share

    def mark_share_key_verified(self, share_id: int, verified_at: Optional[str] = None) -> Optional[DocumentShare]:
        share = self.get_direct_share_by_id(share_id)
        if not share or share.active != 1:
            return None
        now = verified_at or datetime.now(timezone.utc).isoformat()
        share.share_key_verified_at = now
        share.updated_at = now
        self.db.commit()
        self.db.refresh(share)
        return share

    def clear_share_key(self, share_id: int) -> Optional[DocumentShare]:
        share = self.get_direct_share_by_id(share_id)
        if not share:
            return None
        self._invalidate_activation("direct", share.id)
        share.share_key_hash = None
        share.share_key_required = 0
        share.share_key_verified_at = None
        share.share_key_created_at = None
        share.share_key_rotated_at = None
        share.updated_at = datetime.now(timezone.utc).isoformat()
        self.db.commit()
        self.db.refresh(share)
        return share

    def get_active_direct_share(self, document_id: int, target_user_id: int) -> Optional[DocumentShare]:
        return self.db.query(DocumentShare).filter(
            DocumentShare.document_id == document_id,
            DocumentShare.target_user_id == target_user_id,
            DocumentShare.active == 1
        ).first()

    def list_active_direct_shares_for_document(self, document_id: int) -> List[DocumentShare]:
        return self.db.query(DocumentShare).filter(
            DocumentShare.document_id == document_id,
            DocumentShare.active == 1
        ).all()

    def list_shares_for_user(self, target_user_id: int) -> List[DocumentShare]:
        return self.db.query(DocumentShare).filter(
            DocumentShare.target_user_id == target_user_id,
            DocumentShare.active == 1
        ).all()

    def revoke_direct_share(
        self,
        share_id: int,
        document_id: int
    ) -> Optional[DocumentShare]:
        share = self.db.query(DocumentShare).filter(
            DocumentShare.id == share_id,
            DocumentShare.document_id == document_id
        ).first()
        if share and share.active == 1:
            share.active = 0
            share.revoked_at = datetime.now(timezone.utc).isoformat()
            # Revocation invalidates any prior Share Key verification.
            share.share_key_verified_at = None
            self.db.commit()
            self.db.refresh(share)
        return share

    def update_direct_share_permission(
        self,
        share_id: int,
        document_id: int,
        new_permission: str
    ) -> Optional[DocumentShare]:
        share = self.db.query(DocumentShare).filter(
            DocumentShare.id == share_id,
            DocumentShare.document_id == document_id
        ).first()
        if share and share.active == 1:
            self._invalidate_activation("direct", share.id)
            share.permission = new_permission
            share.updated_at = datetime.now(timezone.utc).isoformat()
            self.db.commit()
            self.db.refresh(share)
        return share

    # --- Group Document Share Methods ---

    def create_group_share(
        self,
        document_id: int,
        group_id: int,
        owner_id: int,
        permission: str = "READ"
    ) -> GroupDocumentShare:
        existing = self.db.query(GroupDocumentShare).filter(
            GroupDocumentShare.document_id == document_id,
            GroupDocumentShare.group_id == group_id
        ).first()

        now = datetime.now(timezone.utc).isoformat()

        if existing:
            self._invalidate_activation("group", existing.id)
            existing.permission = permission
            existing.active = 1
            existing.revoked_at = None
            existing.updated_at = now
            self.db.commit()
            self.db.refresh(existing)
            return existing

        share = GroupDocumentShare(
            document_id=document_id,
            group_id=group_id,
            owner_id=owner_id,
            permission=permission,
            active=1,
            created_at=now,
            updated_at=now
        )
        self.db.add(share)
        self.db.commit()
        self.db.refresh(share)
        return share

    def get_active_group_shares_for_groups(self, document_id: int, group_ids: List[int]) -> List[GroupDocumentShare]:
        if not group_ids:
            return []
        return self.db.query(GroupDocumentShare).filter(
            GroupDocumentShare.document_id == document_id,
            GroupDocumentShare.group_id.in_(group_ids),
            GroupDocumentShare.active == 1
        ).all()

    def list_group_shares_for_document(self, document_id: int) -> List[GroupDocumentShare]:
        return self.db.query(GroupDocumentShare).filter(
            GroupDocumentShare.document_id == document_id,
            GroupDocumentShare.active == 1
        ).all()

    def get_group_share_by_id(self, share_id: int) -> Optional[GroupDocumentShare]:
        return self.db.query(GroupDocumentShare).filter(GroupDocumentShare.id == share_id).first()

    def update_group_share_permission(
        self,
        share_id: int,
        document_id: int,
        new_permission: str
    ) -> Optional[GroupDocumentShare]:
        share = self.db.query(GroupDocumentShare).filter(
            GroupDocumentShare.id == share_id,
            GroupDocumentShare.document_id == document_id
        ).first()
        if share and share.active == 1:
            self._invalidate_activation("group", share.id)
            share.permission = new_permission
            share.updated_at = datetime.now(timezone.utc).isoformat()
            self.db.commit()
            self.db.refresh(share)
        return share

    def revoke_group_share(self, share_id: int, document_id: Optional[int] = None) -> Optional[GroupDocumentShare]:
        query = self.db.query(GroupDocumentShare).filter(GroupDocumentShare.id == share_id)
        if document_id is not None:
            query = query.filter(GroupDocumentShare.document_id == document_id)
        share = query.first()
        if share and share.active == 1:
            share.active = 0
            share.revoked_at = datetime.now(timezone.utc).isoformat()
            self.db.commit()
            self.db.refresh(share)
        return share
