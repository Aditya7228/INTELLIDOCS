from typing import Optional, Set, Dict
import json
from sqlalchemy.orm import Session
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.document_share import DocumentShare
from backend.models.group import GroupDocumentShare
from backend.models.security_assessment import SecurityAssessmentModel
from backend.models.share_access_activation import ShareAccessActivation
from backend.database.repositories.share_repo import ShareRepository
from backend.database.repositories.group_repo import GroupRepository
from backend.security.jwt_handler import JWTHandler

PERM_LEVELS = {
    "NONE": 0,
    "READ": 1,
    "APPEND": 2,
    "WRITE": 3,
    "OWNER": 4,
}


class PermissionService:
    @staticmethod
    def latest_document_assessment(db: Session, doc: DocumentModel):
        if db is None or not doc or not getattr(doc, "id", None):
            return None
        return (
            db.query(SecurityAssessmentModel)
            .filter(SecurityAssessmentModel.document_id == doc.id)
            .order_by(SecurityAssessmentModel.created_at.desc(), SecurityAssessmentModel.id.desc())
            .first()
        )

    @staticmethod
    def is_document_security_cleared(db: Session, doc: DocumentModel) -> bool:
        """Require a linked SAFE/PROMOTED upload assessment before shared access."""
        assessment = PermissionService.latest_document_assessment(db, doc)
        if not assessment:
            return False
        verdict = str(getattr(assessment, "verdict", "") or "").upper()
        quarantine_status = str(getattr(assessment, "quarantine_status", "") or "").upper()
        return verdict == "SAFE" and quarantine_status == "PROMOTED"

    @staticmethod
    def is_share_activated(db: Session, source_type: str, share_id: int, user_id: int, doc: DocumentModel = None) -> bool:
        """True only when this recipient reviewed the current linked assessment."""
        if db is None:
            # Keep small permission-service unit tests that deliberately use no DB compatible.
            return True
        assessment = PermissionService.latest_document_assessment(db, doc) if doc is not None else None
        if not assessment:
            return False
        activation = db.query(ShareAccessActivation).filter(
            ShareAccessActivation.source_type == source_type,
            ShareAccessActivation.share_id == share_id,
            ShareAccessActivation.user_id == user_id,
        ).first()
        if not activation or activation.assessment_id != assessment.id:
            return False
        scanner_status = str(getattr(assessment, "scanner_status", "") or "").upper()
        if scanner_status != "AVAILABLE" and not bool(activation.limited_checks_acknowledged):
            return False
        return True

    @staticmethod
    def has_pending_share_access(db: Session, user: User, doc: DocumentModel) -> bool:
        """Allow a recipient to verify an Access Lock while the share is still pending.

        This grants no document read/download permission by itself; it is used only
        by the Access Lock key-verification endpoint and the security-review route.
        """
        if not db or not user or not doc or doc.owner_id == user.id:
            return False
        repo = ShareRepository(db)
        direct = repo.get_active_direct_share(doc.id, user.id)
        if direct and (not bool(direct.share_key_required) or bool(direct.share_key_verified_at)):
            return True
        group_repo = GroupRepository(db)
        group_ids = group_repo.get_user_group_ids(user.id)
        if group_ids:
            return bool(repo.get_active_group_shares_for_groups(doc.id, group_ids))
        return False

    @staticmethod
    def get_user_permission(db: Session, user: User, doc: DocumentModel) -> str:
        if not user or not doc:
            return "NONE"

        # Owners keep managing their own files. Shared recipients are subject to
        # the linked assessment and explicit recipient-specific activation.
        if doc.owner_id == user.id:
            return "OWNER"
        if db is not None and not PermissionService.is_document_security_cleared(db, doc):
            return "NONE"

        highest_level = 0
        highest_perm = "NONE"
        share_repo = ShareRepository(db)

        # 1. Active direct share: both Share Key verification and acceptance required.
        direct_share = share_repo.get_active_direct_share(doc.id, user.id)
        direct_key_blocked = (
            direct_share is not None
            and bool(getattr(direct_share, "share_key_required", 0))
            and not bool(getattr(direct_share, "share_key_verified_at", None))
        )
        direct_activated = bool(
            direct_share and PermissionService.is_share_activated(
                db, "direct", getattr(direct_share, "id", None), user.id, doc
            )
        )
        if direct_share and not direct_key_blocked and direct_activated:
            p = str(direct_share.permission or "NONE").upper()
            level = PERM_LEVELS.get(p, 0)
            if level > highest_level:
                highest_level, highest_perm = level, p

        # 2. Each member of a shared group must activate that group's grant separately.
        group_repo = GroupRepository(db)
        user_group_ids = group_repo.get_user_group_ids(user.id)
        if user_group_ids:
            group_shares = share_repo.get_active_group_shares_for_groups(doc.id, user_group_ids)
            for gs in group_shares:
                if not PermissionService.is_share_activated(db, "group", getattr(gs, "id", None), user.id, doc):
                    continue
                p = str(gs.permission or "NONE").upper()
                level = PERM_LEVELS.get(p, 0)
                if level > highest_level:
                    highest_level, highest_perm = level, p

        # Preserve the existing project policy: administrators retain read access
        # as an independent privileged role, not because of a pending share.
        if highest_level == 0 and getattr(user, "role", None) == "admin":
            return "READ"
        return highest_perm

    @staticmethod
    def can_read(db: Session, user: User, doc: DocumentModel) -> bool:
        perm = PermissionService.get_user_permission(db, user, doc)
        return PERM_LEVELS.get(perm, 0) >= PERM_LEVELS["READ"]

    @staticmethod
    def can_append(db: Session, user: User, doc: DocumentModel) -> bool:
        perm = PermissionService.get_user_permission(db, user, doc)
        return PERM_LEVELS.get(perm, 0) >= PERM_LEVELS["APPEND"]

    @staticmethod
    def can_write(db: Session, user: User, doc: DocumentModel) -> bool:
        perm = PermissionService.get_user_permission(db, user, doc)
        return PERM_LEVELS.get(perm, 0) >= PERM_LEVELS["WRITE"]

    @staticmethod
    def is_owner(db: Session, user: User, doc: DocumentModel) -> bool:
        return PermissionService.get_user_permission(db, user, doc) == "OWNER"

    @staticmethod
    def check_access_lock(db: Session, user: User, doc: DocumentModel, lock_token: Optional[str] = None) -> bool:
        """Check the document-wide lock independently from share activation."""
        if not doc or not getattr(doc, "is_access_locked", 0) or not getattr(doc, "access_lock_hash", None):
            return True
        if doc.owner_id == user.id:
            return True
        if not lock_token:
            return False
        return JWTHandler.verify_access_lock_token(lock_token, doc.uuid, user.id, doc.access_lock_hash)

    @staticmethod
    def parse_request_lock_tokens(request) -> Dict[str, str]:
        """Parse per-document unlock tokens supplied by the authenticated UI.

        Tokens are never trusted by presence alone: every token is cryptographically
        checked against the candidate document UUID, recipient ID and current lock hash
        by resolve_access_lock_token/check_access_lock before it can grant access.
        """
        try:
            headers = getattr(request, "headers", None)
            raw = headers.get("X-Access-Lock-Tokens") if headers is not None else None
            if not raw or len(raw) > 12_000:
                return {}
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return {}
            result = {}
            for key, token in list(payload.items())[:32]:
                if not isinstance(key, str) or not key or len(key) > 128:
                    continue
                if isinstance(token, str) and token and len(token) <= 4096:
                    result[key] = token
            return result
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    @staticmethod
    def resolve_access_lock_token(
        db: Session,
        user: User,
        doc: DocumentModel,
        lock_tokens: Optional[Dict[str, str]] = None,
        fallback_token: Optional[str] = None,
    ) -> Optional[str]:
        """Return a valid token for this exact document, or None.

        A single focused-document token is only accepted if it is valid for this
        document. A map supports several independently unlocked received documents.
        Unlocked documents need no token; callers still enforce check_access_lock.
        """
        if not doc or not user:
            return None
        if doc.owner_id == user.id:
            return None
        if not getattr(doc, "is_access_locked", 0) or not getattr(doc, "access_lock_hash", None):
            return None
        candidates = []
        if lock_tokens:
            candidates.extend([
                lock_tokens.get(str(getattr(doc, "uuid", ""))),
                lock_tokens.get(str(getattr(doc, "id", ""))),
            ])
        candidates.append(fallback_token)
        seen = set()
        for token in candidates:
            if not isinstance(token, str) or not token or token in seen:
                continue
            seen.add(token)
            if PermissionService.check_access_lock(db, user, doc, token):
                return token
        return None

    @staticmethod
    def list_accessible_document_ids(db: Session, user_id: int) -> Set[int]:
        """Return owned documents plus shared documents this user has activated."""
        accessible_ids: Set[int] = set()

        owned = db.query(DocumentModel.id).filter(
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0,
        ).all()
        accessible_ids.update(row[0] for row in owned)

        repo = ShareRepository(db)
        for share in repo.list_shares_for_user(user_id):
            if share.active != 1:
                continue
            if bool(share.share_key_required) and not share.share_key_verified_at:
                continue
            doc = db.query(DocumentModel).filter(
                DocumentModel.id == share.document_id,
                DocumentModel.is_deleted == 0,
            ).first()
            permission = str(getattr(share, "permission", "NONE") or "NONE").upper()
            if (
                doc
                and permission in {"READ", "APPEND", "WRITE"}
                and PermissionService.is_document_security_cleared(db, doc)
                and PermissionService.is_share_activated(db, "direct", share.id, user_id, doc)
            ):
                accessible_ids.add(doc.id)

        group_ids = GroupRepository(db).get_user_group_ids(user_id)
        if group_ids:
            group_shares = db.query(GroupDocumentShare).filter(
                GroupDocumentShare.group_id.in_(group_ids),
                GroupDocumentShare.active == 1,
            ).all()
            for share in group_shares:
                doc = db.query(DocumentModel).filter(
                    DocumentModel.id == share.document_id,
                    DocumentModel.is_deleted == 0,
                ).first()
                permission = str(getattr(share, "permission", "NONE") or "NONE").upper()
                if (
                    doc
                    and permission in {"READ", "APPEND", "WRITE"}
                    and PermissionService.is_document_security_cleared(db, doc)
                    and PermissionService.is_share_activated(db, "group", share.id, user_id, doc)
                ):
                    accessible_ids.add(doc.id)

        return accessible_ids
