import json
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.database.repositories.group_repo import GroupRepository
from backend.schemas.share_schema import (
    ShareCreateRequest,
    ShareUpdatePermissionRequest,
    ShareOut,
    UserSearchOut,
    ShareKeyVerifyRequest,
    ShareKeyStatusOut,
    ShareActivationRequest,
)
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.document_share import DocumentShare
from backend.models.group import GroupDocumentShare
from backend.models.security_assessment import SecurityAssessmentModel
from backend.models.share_access_activation import ShareAccessActivation
from backend.api.deps import get_current_user
from backend.core.permission_service import PermissionService
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService
from backend.security.share_key_service import ShareKeyService
from backend.security.access_lock_limiter import AccessLockLimiter
from backend.security.path_guard import PathGuard
from backend.security.security_assessment_service import SecurityAssessmentService

router = APIRouter(tags=["Document Sharing"])
# Independent in-memory throttle for recipient-bound Share Keys.
share_key_limiter = AccessLockLimiter(max_attempts=5, lock_duration_sec=900)

def _shared_document_security_fields(db: Session, doc: DocumentModel) -> dict:
    """Return a minimal upload-assessment summary; do not expose private findings or PII."""
    assessment = (
        db.query(SecurityAssessmentModel)
        .filter(SecurityAssessmentModel.document_id == doc.id)
        .order_by(SecurityAssessmentModel.created_at.desc(), SecurityAssessmentModel.id.desc())
        .first()
    )
    status_label = "NOT_ASSESSED"
    verdict = risk_level = scanner_status = confidence = assessed_at = None
    if assessment:
        verdict = str(assessment.verdict or "").upper() or None
        risk_level = assessment.risk_level
        scanner_status = str(assessment.scanner_status or "").upper() or None
        confidence = assessment.confidence
        assessed_at = assessment.created_at
        quarantine_status = str(assessment.quarantine_status or "").upper()
        if verdict == "BLOCKED" or quarantine_status == "BLOCKED":
            status_label = "BLOCKED"
        elif verdict == "SUSPICIOUS" or quarantine_status == "QUARANTINED":
            status_label = "QUARANTINED"
        elif verdict == "SAFE" and quarantine_status == "PROMOTED":
            status_label = "PASSED" if scanner_status == "AVAILABLE" else "LIMITED"
        else:
            status_label = "REVIEW"
    return {
        "access_locked": bool(getattr(doc, "is_access_locked", 0) and getattr(doc, "access_lock_hash", None)),
        "security_status": status_label,
        "security_verdict": verdict,
        "security_risk_level": risk_level,
        "security_scanner_status": scanner_status,
        "security_confidence": confidence,
        "security_assessed_at": assessed_at,
    }

@router.get("/users/search", response_model=List[UserSearchOut])
@router.get("/shares/users/search", response_model=List[UserSearchOut])
def search_users_for_sharing(
    q: str = Query("", min_length=0, max_length=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Search registered users by username or email for document sharing.
    Excludes the current user and returns only safe public profile fields (id, username, email).
    """
    if not q or not q.strip():
        return []

    user_repo = UserRepository(db)
    users = user_repo.search_users(query=q.strip(), exclude_user_id=current_user.id, limit=10)
    return [UserSearchOut(id=u.id, username=u.username, email=u.email) for u in users]


@router.post("/documents/{uuid}/shares", response_model=List[ShareOut], status_code=status.HTTP_201_CREATED)
def share_document(
    uuid: str,
    data: ShareCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can share this document")

    if not PermissionService.is_document_security_cleared(db, doc):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document sharing is disabled until its security assessment is SAFE and PROMOTED.",
        )

    user_repo = UserRepository(db)
    share_repo = ShareRepository(db)

    # Validate the entire recipient list before creating shares. Repository share
    # methods commit independently, so validating inside the creation loop can leave
    # partial grants when a later recipient is invalid.
    targets = []
    for target_str in data.target_users:
        target_user = user_repo.get_by_username(target_str) or user_repo.get_by_email(target_str)
        if not target_user:
            raise HTTPException(status_code=400, detail=f"User '{target_str}' not found")
        if target_user.id == current_user.id:
            raise HTTPException(status_code=400, detail="You cannot share a document with yourself")
        targets.append(target_user)

    results = []
    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    for target_user in targets:
        share = share_repo.create_direct_share(
            document_id=doc.id,
            owner_id=current_user.id,
            target_user_id=target_user.id,
            permission=data.permission,
            share_key_required=int(data.protect_with_key),
        )

        issued_share_key = None
        if data.protect_with_key:
            issued_share_key = ShareKeyService.generate_key()
            key_hash = ShareKeyService.hash_key(share.id, target_user.id, issued_share_key)
            share_repo.set_share_key(
                share.id,
                key_hash,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            share = share_repo.get_direct_share_by_id(share.id)
        else:
            share_repo.clear_share_key(share.id)
            share = share_repo.get_direct_share_by_id(share.id)

        AuditService.log(
            db, action="DOCUMENT_SHARE_CREATED", user_id=current_user.id,
            resource_type="document", resource_id=doc.uuid,
            ip_address=ip_addr, user_agent=user_agent,
            detail={"target_username": target_user.username, "permission": data.permission}
        )

        doc_title = doc.display_name or doc.original_name
        NotificationService.notify(
            db,
            user_id=target_user.id,
            event_type="DOCUMENT_SHARED",
            title="Document Shared With You",
            message=f"{current_user.username} shared '{doc_title}' with you ({data.permission} permission)",
            document_id=doc.id
        )

        results.append(ShareOut(
            id=share.id,
            document_id=doc.id,
            document_uuid=doc.uuid,
            document_name=doc_title,
            owner_id=current_user.id,
            owner_username=current_user.username,
            target_user_id=target_user.id,
            target_username=target_user.username,
            target_email=target_user.email,
            permission=share.permission,
            source="direct",
            created_at=share.created_at,
            updated_at=share.updated_at,
            revoked_at=share.revoked_at,
            active=bool(share.active),
            share_key_required=bool(share.share_key_required),
            share_key_verified=(not bool(share.share_key_required)) or bool(share.share_key_verified_at),
            share_key=issued_share_key,
            share_key_created_at=share.share_key_created_at,
            share_key_rotated_at=share.share_key_rotated_at,
        ))

    return results


@router.get("/documents/{uuid}/shares", response_model=List[ShareOut])
def list_document_shares(
    uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can view sharing settings")

    share_repo = ShareRepository(db)
    user_repo = UserRepository(db)
    group_repo = GroupRepository(db)

    out = []
    doc_title = doc.display_name or doc.original_name

    # Direct Shares
    direct_shares = share_repo.list_active_direct_shares_for_document(doc.id)
    for s in direct_shares:
        target = user_repo.get_by_id(s.target_user_id)
        if target:
            out.append(ShareOut(
                id=s.id,
                document_id=doc.id,
                document_uuid=doc.uuid,
                document_name=doc_title,
                owner_id=doc.owner_id,
                owner_username=current_user.username,
                target_user_id=target.id,
                target_username=target.username,
                target_email=target.email,
                permission=s.permission,
                source="direct",
                created_at=s.created_at,
                updated_at=s.updated_at,
                revoked_at=s.revoked_at,
                active=bool(s.active),
                share_key_required=bool(s.share_key_required),
                share_key_verified=(not bool(s.share_key_required)) or bool(s.share_key_verified_at),
                share_key_created_at=s.share_key_created_at,
                share_key_rotated_at=s.share_key_rotated_at
            ))

    # Group Shares
    group_shares = share_repo.list_group_shares_for_document(doc.id)
    for gs in group_shares:
        grp = group_repo.get_group_by_id(gs.group_id)
        if grp:
            members = group_repo.list_group_members(grp.id)
            for m in members:
                target = user_repo.get_by_id(m.user_id)
                if target:
                    out.append(ShareOut(
                        id=gs.id,
                        document_id=doc.id,
                        document_uuid=doc.uuid,
                        document_name=doc_title,
                        owner_id=doc.owner_id,
                        owner_username=current_user.username,
                        target_user_id=target.id,
                        target_username=target.username,
                        target_email=target.email,
                        permission=gs.permission,
                        source="group",
                        group_name=grp.name,
                        group_id=gs.group_id,
                        **_shared_document_security_fields(db, doc),
                        created_at=gs.created_at,
                        updated_at=gs.updated_at,
                        revoked_at=gs.revoked_at,
                        active=bool(gs.active)
                    ))

    return out


@router.post("/documents/{uuid}/shares/{share_id}/verify-key")
def verify_share_key(
    uuid: str,
    share_id: int,
    data: ShareKeyVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = DocumentRepository(db).get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    share_repo = ShareRepository(db)
    share = share_repo.get_direct_share_by_id(share_id)
    if not share or share.document_id != doc.id or share.active != 1:
        raise HTTPException(status_code=404, detail="Active direct share not found")
    if share.target_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only the intended recipient can verify this Share Key")
    if not bool(share.share_key_required):
        return {"share_id": share.id, "required": False, "verified": True}
    if not share.share_key_hash:
        raise HTTPException(status_code=409, detail="Share Key is required but no active key is configured. Ask the owner to rotate the key.")
    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    is_blocked, remaining_sec = share_key_limiter.is_blocked(share.id, current_user.id, ip_addr)
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many incorrect Share Key attempts. Temporarily locked for {remaining_sec} seconds."
        )

    valid = ShareKeyService.verify_key(share.id, current_user.id, data.key, share.share_key_hash)
    if not valid:
        _, threshold_exceeded = share_key_limiter.record_failure(share.id, current_user.id, ip_addr)
        AuditService.log(db, action="DOCUMENT_SHARE_KEY_VERIFICATION_FAILED", user_id=current_user.id, resource_type="document", resource_id=doc.uuid, ip_address=ip_addr, user_agent=user_agent, detail={"share_id": share.id}, success=0)
        if threshold_exceeded:
            AuditService.log(db, action="DOCUMENT_SHARE_KEY_FAILURE_THRESHOLD", user_id=current_user.id, resource_type="document", resource_id=doc.uuid, ip_address=ip_addr, user_agent=user_agent, detail={"share_id": share.id}, success=0)
            NotificationService.notify(
                db, user_id=doc.owner_id, event_type="DOCUMENT_SHARE_KEY_FAILURE_THRESHOLD",
                title="Repeated Share Key Failures",
                message=f"Repeated invalid Share Key attempts were detected for '{doc.display_name or doc.original_name}'.",
                document_id=doc.id
            )
        raise HTTPException(status_code=403, detail="Invalid Share Key")

    share_key_limiter.record_success(share.id, current_user.id, ip_addr)
    verified_at = datetime.now(timezone.utc).isoformat()
    share_repo.mark_share_key_verified(share.id, verified_at=verified_at)
    AuditService.log(db, action="DOCUMENT_SHARE_KEY_VERIFIED", user_id=current_user.id, resource_type="document", resource_id=doc.uuid, ip_address=ip_addr, user_agent=user_agent, detail={"share_id": share.id}, success=1)
    return {"share_id": share.id, "required": True, "verified": True, "verified_at": verified_at}


@router.get("/documents/{uuid}/shares/{share_id}/key-status", response_model=ShareKeyStatusOut)
def get_share_key_status(
    uuid: str,
    share_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = DocumentRepository(db).get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    share = ShareRepository(db).get_direct_share_by_id(share_id)
    if not share or share.document_id != doc.id or share.active != 1:
        raise HTTPException(status_code=404, detail="Active direct share not found")
    if not PermissionService.is_owner(db, current_user, doc) and share.target_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to inspect this Share Key")
    return ShareKeyStatusOut(share_id=share.id, required=bool(share.share_key_required), verified=(True if not share.share_key_required else bool(share.share_key_verified_at)), created_at=share.share_key_created_at, rotated_at=share.share_key_rotated_at)


@router.post("/documents/{uuid}/shares/{share_id}/rotate-key")
def rotate_share_key(
    uuid: str,
    share_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = DocumentRepository(db).get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can rotate a Share Key")
    share_repo = ShareRepository(db)
    share = share_repo.get_direct_share_by_id(share_id)
    if not share or share.document_id != doc.id or share.active != 1:
        raise HTTPException(status_code=404, detail="Active direct share not found")
    if not bool(share.share_key_required):
        raise HTTPException(status_code=400, detail="Share Key protection is not enabled for this share.")
    raw_key = ShareKeyService.generate_key()
    key_hash = ShareKeyService.hash_key(share.id, share.target_user_id, raw_key)
    now = datetime.now(timezone.utc).isoformat()
    share_repo.set_share_key(share.id, key_hash, created_at=share.share_key_created_at or now, rotated_at=now)
    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    AuditService.log(db, action="DOCUMENT_SHARE_KEY_ROTATED", user_id=current_user.id, resource_type="document", resource_id=doc.uuid, ip_address=ip_addr, user_agent=user_agent, detail={"share_id": share.id}, success=1)
    return {"share_id": share.id, "required": True, "verified": False, "share_key": raw_key, "rotated_at": now}


@router.put("/documents/{uuid}/shares/{share_id}", response_model=ShareOut)
def update_share_permission(
    uuid: str,
    share_id: int,
    data: ShareUpdatePermissionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can change permissions")

    share_repo = ShareRepository(db)
    user_repo = UserRepository(db)
    group_repo = GroupRepository(db)

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    doc_title = doc.display_name or doc.original_name

    updated_direct = share_repo.update_direct_share_permission(share_id, doc.id, data.permission)
    if updated_direct:
        target_user = user_repo.get_by_id(updated_direct.target_user_id)
        AuditService.log(
            db, action="DOCUMENT_PERMISSION_CHANGED", user_id=current_user.id,
            resource_type="document", resource_id=doc.uuid,
            ip_address=ip_addr, user_agent=user_agent,
            detail={"target_username": target_user.username if target_user else None, "new_permission": data.permission}
        )
        if target_user:
            NotificationService.notify(
                db,
                user_id=target_user.id,
                event_type="PERMISSION_CHANGED",
                title="Document Permission Changed",
                message=f"{current_user.username} changed your permission on '{doc_title}' to {data.permission}",
                document_id=doc.id
            )
        return ShareOut(
            id=updated_direct.id,
            document_id=doc.id,
            document_uuid=doc.uuid,
            document_name=doc_title,
            owner_id=doc.owner_id,
            owner_username=current_user.username,
            target_user_id=target_user.id if target_user else 0,
            target_username=target_user.username if target_user else "Unknown",
            target_email=target_user.email if target_user else "",
            permission=updated_direct.permission,
            source="direct",
            created_at=updated_direct.created_at,
            updated_at=updated_direct.updated_at,
            revoked_at=updated_direct.revoked_at,
            active=bool(updated_direct.active),
            share_key_required=bool(updated_direct.share_key_required),
            share_key_verified=(not bool(updated_direct.share_key_required)) or bool(updated_direct.share_key_verified_at),
            share_key_created_at=updated_direct.share_key_created_at,
            share_key_rotated_at=updated_direct.share_key_rotated_at
        )

    updated_group = share_repo.update_group_share_permission(share_id, doc.id, data.permission)
    if updated_group:
        grp = group_repo.get_group_by_id(updated_group.group_id)
        AuditService.log(
            db, action="GROUP_SHARE_PERMISSION_CHANGED", user_id=current_user.id,
            resource_type="document", resource_id=doc.uuid,
            ip_address=ip_addr, user_agent=user_agent,
            detail={"group_name": grp.name if grp else "Group", "new_permission": data.permission}
        )
        if grp:
            members = group_repo.list_group_members(grp.id)
            for m in members:
                if m.user_id != current_user.id:
                    NotificationService.notify(
                        db,
                        user_id=m.user_id,
                        event_type="GROUP_PERMISSION_CHANGED",
                        title="Group Permission Changed",
                        message=f"{current_user.username} changed group permission for '{doc_title}' to {data.permission}",
                        document_id=doc.id
                    )
        return ShareOut(
            id=updated_group.id,
            document_id=doc.id,
            document_uuid=doc.uuid,
            document_name=doc_title,
            owner_id=doc.owner_id,
            owner_username=current_user.username,
            target_user_id=0,
            target_username=grp.name if grp else "Group",
            target_email=f"group_{updated_group.group_id}@intellidocs.local",
            permission=updated_group.permission,
            source="group",
            group_name=grp.name if grp else "Group",
            group_id=updated_group.group_id,
            **_shared_document_security_fields(db, doc),
            created_at=updated_group.created_at,
            updated_at=updated_group.updated_at,
            revoked_at=updated_group.revoked_at,
            active=bool(updated_group.active)
        )

    raise HTTPException(status_code=404, detail="Active share not found")


@router.delete("/documents/{uuid}/shares/{share_id}", status_code=status.HTTP_200_OK)
def revoke_share(
    uuid: str,
    share_id: int,
    request: Request,
    source: Optional[str] = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can revoke sharing")

    share_repo = ShareRepository(db)
    user_repo = UserRepository(db)
    group_repo = GroupRepository(db)

    requested_source = str(source or "").strip().lower()
    if requested_source not in ("", "direct", "group"):
        raise HTTPException(status_code=400, detail="Invalid share source")

    # Numeric IDs are generated independently by the direct- and group-share tables.
    # Resolve candidates against both source and document before choosing a grant.
    direct_candidate = share_repo.get_direct_share_by_id(share_id)
    if (
        not direct_candidate
        or direct_candidate.document_id != doc.id
        or int(direct_candidate.active or 0) != 1
    ):
        direct_candidate = None

    group_candidate = share_repo.get_group_share_by_id(share_id)
    if (
        not group_candidate
        or group_candidate.document_id != doc.id
        or int(group_candidate.active or 0) != 1
    ):
        group_candidate = None

    if not requested_source:
        if direct_candidate and group_candidate:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Share ID is ambiguous; specify source=direct or source=group.",
            )
        if direct_candidate:
            requested_source = "direct"
        elif group_candidate:
            requested_source = "group"
        else:
            raise HTTPException(status_code=404, detail="Active share not found or already revoked")

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    doc_title = doc.display_name or doc.original_name

    if requested_source == "direct":
        if not direct_candidate:
            raise HTTPException(status_code=404, detail="Active direct share not found or already revoked")
        revoked_direct = share_repo.revoke_direct_share(share_id, doc.id)
        if not revoked_direct:
            raise HTTPException(status_code=404, detail="Active direct share not found or already revoked")

        target_user = user_repo.get_by_id(revoked_direct.target_user_id)
        AuditService.log(
            db, action="DOCUMENT_SHARE_REVOKED", user_id=current_user.id,
            resource_type="document", resource_id=doc.uuid,
            ip_address=ip_addr, user_agent=user_agent,
            detail={"target_username": target_user.username if target_user else None}
        )
        if target_user:
            NotificationService.notify(
                db,
                user_id=target_user.id,
                event_type="DOCUMENT_ACCESS_REVOKED",
                title="Document Access Revoked",
                message=f"{current_user.username} revoked your access to '{doc_title}'",
                document_id=doc.id
            )
        return {"detail": f"Access to '{doc_title}' has been revoked successfully."}

    if not group_candidate:
        raise HTTPException(status_code=404, detail="Active group share not found or already revoked")
    revoked_group = share_repo.revoke_group_share(share_id, doc.id)
    if not revoked_group:
        raise HTTPException(status_code=404, detail="Active group share not found or already revoked")

    grp = group_repo.get_group_by_id(revoked_group.group_id)
    AuditService.log(
        db, action="GROUP_DOCUMENT_SHARE_REVOKED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent,
        detail={"group_name": grp.name if grp else "Group"}
    )
    if grp:
        members = group_repo.list_group_members(grp.id)
        for m in members:
            if m.user_id != current_user.id:
                NotificationService.notify(
                    db,
                    user_id=m.user_id,
                    event_type="GROUP_ACCESS_REVOKED",
                    title="Group Document Access Revoked",
                    message=f"{current_user.username} revoked access to '{doc_title}' for group '{grp.name}'",
                    document_id=doc.id
                )
    return {"detail": f"Access to '{doc_title}' for group '{grp.name if grp else 'Group'}' has been revoked successfully."}


def _resolve_recipient_share(db: Session, source: str, share_id: int, current_user: User):
    """Resolve a pending grant only for its intended direct recipient/group member."""
    repo = ShareRepository(db)
    group_repo = GroupRepository(db)
    doc_repo = DocumentRepository(db)
    source = str(source or "").strip().lower()
    if source == "direct":
        share = repo.get_direct_share_by_id(share_id)
        if not share or share.active != 1 or share.target_user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Active received share not found")
        doc = doc_repo.get_by_id(share.document_id)
    elif source == "group":
        share = repo.get_group_share_by_id(share_id)
        if not share or share.active != 1:
            raise HTTPException(status_code=404, detail="Active received group share not found")
        if not group_repo.get_member(share.group_id, current_user.id):
            raise HTTPException(status_code=404, detail="Active received group share not found")
        doc = doc_repo.get_by_id(share.document_id)
    else:
        raise HTTPException(status_code=404, detail="Share source not found")
    if not doc or doc.is_deleted:
        raise HTTPException(status_code=404, detail="Shared document not found")
    return source, share, doc


def _activation_assessment_payload(db: Session, doc: DocumentModel) -> dict:
    assessment = PermissionService.latest_document_assessment(db, doc)
    if not assessment:
        return {
            "security_status": "NOT_ASSESSED", "security_verdict": None,
            "security_quarantine_status": None, "security_risk_score": None,
            "security_risk_level": None, "security_confidence": None,
            "security_scanner_status": None, "security_scanner_detail": None,
            "security_assessed_at": None,
            "data_sensitivity": None, "pii_detected": False,
            "check_states": {}, "findings": [], "recommended_action": "Do not activate: no linked security assessment is available.",
        }

    verdict = str(assessment.verdict or "").upper()
    quarantine_status = str(assessment.quarantine_status or "").upper()
    scanner_status = str(assessment.scanner_status or "").upper()
    if verdict == "BLOCKED" or quarantine_status == "BLOCKED":
        label = "BLOCKED"
    elif verdict == "SUSPICIOUS" or quarantine_status == "QUARANTINED":
        label = "QUARANTINED"
    elif verdict == "SAFE" and quarantine_status == "PROMOTED":
        label = "PASSED" if scanner_status == "AVAILABLE" else "LIMITED"
    else:
        label = "REVIEW"

    try:
        raw_checks = json.loads(assessment.check_states_json or "{}")
        raw_checks = raw_checks if isinstance(raw_checks, dict) else {}
    except (TypeError, ValueError):
        raw_checks = {}
    # Expose only the scanner adapter's bounded diagnostic; it contains status
    # detail, not arbitrary file content, raw findings, or machine paths.
    raw_scanner_detail = raw_checks.get("malware_scan_detail")
    scanner_detail = (
        raw_scanner_detail.strip()[:400]
        if isinstance(raw_scanner_detail, str) and raw_scanner_detail.strip()
        else None
    )
    # Report only check states, not arbitrary nested evidence that could contain
    # source text, PII, paths, or scanner-specific diagnostic detail.
    allowed_state_words = {
        "PASS", "PASSED", "SAFE", "CLEAR", "AVAILABLE", "SKIPPED", "WARNING",
        "WARN", "BLOCKED", "FAIL", "FAILED", "UNAVAILABLE", "NOT_RUN", "ERROR",
        "INFO", "LOW", "MEDIUM", "HIGH", "LIMITED", "REVIEW", "QUARANTINED"
    }
    check_states = {}
    for check_name, raw_state in list(raw_checks.items())[:50]:
        if str(check_name).lower() == "malware_scan_detail":
            continue
        state = raw_state
        if isinstance(raw_state, dict):
            state = next((raw_state.get(key) for key in ("status", "state", "verdict", "result", "passed") if raw_state.get(key) is not None), None)
        if isinstance(state, bool):
            safe_state = "PASSED" if state else "FAILED"
        elif isinstance(state, (int, float)):
            safe_state = state
        elif isinstance(state, str) and state.strip().upper() in allowed_state_words:
            safe_state = state.strip().upper()
        else:
            safe_state = "CHECKED"
        check_states[str(check_name)[:80]] = safe_state
    try:
        raw_findings = json.loads(assessment.findings_json or "[]")
        raw_findings = raw_findings if isinstance(raw_findings, list) else []
    except (TypeError, ValueError):
        raw_findings = []
    # Share only sanitized finding labels. Do not expose technical evidence or PII.
    safe_findings = []
    for item in raw_findings[:50]:
        if isinstance(item, dict):
            safe_findings.append({
                "check_name": str(item.get("check_name") or item.get("check") or "Security check")[:100],
                "title": str(item.get("title") or item.get("message") or "Finding")[:180],
                "severity": str(item.get("severity") or "INFO")[:30],
                "finding_type": str(item.get("finding_type") or item.get("type") or "")[:80],
            })
        elif isinstance(item, str):
            safe_findings.append({"check_name": "Security check", "title": item[:180], "severity": "INFO", "finding_type": ""})

    return {
        "assessment_id": assessment.id,
        "security_status": label,
        "security_verdict": verdict or None,
        "security_quarantine_status": quarantine_status or None,
        "security_risk_score": int(assessment.risk_score or 0),
        "security_risk_level": assessment.risk_level,
        "security_confidence": assessment.confidence,
        "security_scanner_status": scanner_status or None,
        "security_scanner_detail": scanner_detail,
        "security_assessed_at": assessment.created_at,
        "data_sensitivity": assessment.data_sensitivity,
        "pii_detected": bool(assessment.pii_detected),
        "check_states": check_states,
        "findings": safe_findings,
        "recommended_action": assessment.recommended_action or "Review the reported assessment before activating access.",
    }


def _require_share_key_verified(source: str, share):
    """Enforce the recipient-specific Share Key before showing a share report."""
    if source == "direct" and bool(share.share_key_required) and not bool(share.share_key_verified_at):
        raise HTTPException(status_code=403, detail="Verify the recipient-specific Share Key before reviewing or activating this share.")


def _require_access_lock_unlocked(db: Session, doc: DocumentModel, current_user: User, lock_token: Optional[str]):
    """Require an unlock token before activation or protected document access."""
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(status_code=403, detail="Access Lock is enabled. Unlock the document before activating shared access.")


def _require_share_activation_prerequisites(db: Session, source: str, share, doc: DocumentModel, current_user: User, lock_token: Optional[str]):
    _require_share_key_verified(source, share)
    _require_access_lock_unlocked(db, doc, current_user, lock_token)


def _assessment_was_refreshed_recently(assessment, cooldown_seconds: int = 30) -> bool:
    """Avoid running an expensive scan repeatedly if a recipient reopens the report."""
    if not assessment or not getattr(assessment, "created_at", None):
        return False
    value = assessment.created_at
    try:
        when = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - when.astimezone(timezone.utc)).total_seconds()
        return 0 <= age < cooldown_seconds
    except (TypeError, ValueError, OverflowError):
        return False


@router.post("/shares/{source}/{share_id}/refresh-security")
def refresh_received_share_security_assessment(
    source: str,
    share_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Recheck an older limited assessment when the intended recipient reviews it.

    Only runs when the stored scan is not AVAILABLE. The file is read from the
    owner's existing storage path; no second document is added to the recipient's
    library. Assessment details are still returned by the recipient-only report route.
    """
    source, share, doc = _resolve_recipient_share(db, source, share_id, current_user)
    lock_token = request.headers.get("X-Access-Lock-Token") or request.query_params.get("lock_token")
    # Reassessment is a server-side security operation on the owner's stored file.
    # It returns only a sanitized status payload and does not grant document reads.
    _require_share_key_verified(source, share)

    previous = PermissionService.latest_document_assessment(db, doc)
    if previous and str(previous.scanner_status or "").upper() == "AVAILABLE":
        return {"refreshed": False, "reason": "A completed scanner result is already linked.", "assessment_id": previous.id}
    if previous and int(getattr(previous, "rescan_count", 0) or 0) > 0 and _assessment_was_refreshed_recently(previous):
        return {"refreshed": False, "reason": "A recent reassessment is already available.", "assessment_id": previous.id}

    try:
        source_path = PathGuard().safe_upload_path(doc.stored_name)
        if not source_path.exists() or not source_path.is_file():
            raise HTTPException(status_code=409, detail="The owner's stored document is unavailable for reassessment.")
        file_bytes = source_path.read_bytes()
    except HTTPException:
        raise
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="The stored document could not be safely read for reassessment.") from exc

    try:
        refreshed = SecurityAssessmentService().run_assessment(
            db=db,
            filename=doc.original_name,
            content_type=doc.mime_type or "application/octet-stream",
            file_bytes=file_bytes,
            owner_id=doc.owner_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except Exception as exc:
        # Do not turn an assessment execution failure into a clean result.
        raise HTTPException(status_code=503, detail="Security reassessment could not complete. Existing access remains pending.") from exc

    verdict = str(refreshed.verdict or "").upper()
    refreshed.document_id = doc.id
    if verdict == "SAFE":
        refreshed.quarantine_status = "PROMOTED"
    elif verdict == "BLOCKED":
        refreshed.quarantine_status = "BLOCKED"
    else:
        refreshed.quarantine_status = "QUARANTINED"
    refreshed.rescan_count = int(getattr(previous, "rescan_count", 0) or 0) + 1
    db.commit()
    db.refresh(refreshed)

    AuditService.log(
        db, action="SHARED_DOCUMENT_SECURITY_REASSESSED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        detail={"source": source, "share_id": share.id, "assessment_id": refreshed.id,
                "verdict": refreshed.verdict, "scanner_status": refreshed.scanner_status},
    )
    scanner_status = str(refreshed.scanner_status or "").upper()
    refreshed_label = "PASSED" if verdict == "SAFE" and scanner_status == "AVAILABLE" else ("LIMITED" if verdict == "SAFE" else ("BLOCKED" if verdict == "BLOCKED" else "QUARANTINED"))
    return {
        "refreshed": True,
        "assessment_id": refreshed.id,
        "verdict": refreshed.verdict,
        "scanner_status": refreshed.scanner_status,
        "security_status": refreshed_label,
    }


@router.get("/shares/{source}/{share_id}/security-report")
def get_received_share_security_report(
    source: str,
    share_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return a sanitized source-upload assessment to the intended recipient before activation."""
    source, share, doc = _resolve_recipient_share(db, source, share_id, current_user)
    lock_token = request.headers.get("X-Access-Lock-Token") or request.query_params.get("lock_token")
    # The report contains only sanitized assessment metadata, not document content.
    # A separate Access Lock token is still mandatory when activating/opening the share.
    _require_share_key_verified(source, share)
    report = _activation_assessment_payload(db, doc)
    report.update({
        "share_id": share.id,
        "source": source,
        "document_uuid": doc.uuid,
        "document_name": doc.display_name or doc.original_name,
        "permission": str(share.permission or "READ").upper(),
        "access_locked": bool(getattr(doc, "is_access_locked", 0) and getattr(doc, "access_lock_hash", None)),
        "limited_checks_ack_required": report.get("security_status") == "LIMITED",
        "can_activate": report.get("security_verdict") == "SAFE" and report.get("security_quarantine_status") == "PROMOTED",
    })
    return report


@router.post("/shares/{source}/{share_id}/activate")
def activate_received_share(
    source: str,
    share_id: int,
    data: ShareActivationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Activate one recipient's share only after keys, lock and assessment review."""
    source, share, doc = _resolve_recipient_share(db, source, share_id, current_user)
    lock_token = request.headers.get("X-Access-Lock-Token") or request.query_params.get("lock_token")
    _require_share_activation_prerequisites(db, source, share, doc, current_user, lock_token)

    assessment = PermissionService.latest_document_assessment(db, doc)
    if not assessment:
        raise HTTPException(status_code=409, detail="Cannot activate: this document has no linked security assessment.")
    verdict = str(assessment.verdict or "").upper()
    quarantine_status = str(assessment.quarantine_status or "").upper()
    if verdict != "SAFE" or quarantine_status != "PROMOTED":
        raise HTTPException(status_code=409, detail=f"Cannot activate this share: security status is {verdict or 'UNKNOWN'}/{quarantine_status or 'UNKNOWN'}.")

    if int(data.assessment_id) != int(assessment.id):
        raise HTTPException(status_code=409, detail="The security assessment changed or the report is stale. Reload the report and review it again before activation.")

    scanner_status = str(assessment.scanner_status or "").upper()
    limited = scanner_status != "AVAILABLE"
    if limited and not data.acknowledge_limited:
        raise HTTPException(status_code=409, detail="The assessment is marked LIMITED because the malware scanner was unavailable or partial. Review the report and explicitly acknowledge the limitation to continue.")

    activation = db.query(ShareAccessActivation).filter(
        ShareAccessActivation.source_type == source,
        ShareAccessActivation.share_id == share.id,
        ShareAccessActivation.user_id == current_user.id,
    ).first()
    now = datetime.now(timezone.utc).isoformat()
    if activation is None:
        activation = ShareAccessActivation(
            source_type=source, share_id=share.id, user_id=current_user.id,
            assessment_id=assessment.id, activated_at=now,
            limited_checks_acknowledged=int(limited and data.acknowledge_limited),
        )
        db.add(activation)
    else:
        activation.assessment_id = assessment.id
        activation.activated_at = now
        activation.limited_checks_acknowledged = int(limited and data.acknowledge_limited)
    db.commit()

    AuditService.log(
        db, action="SHARED_DOCUMENT_ACCESS_ACTIVATED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        detail={"source": source, "share_id": share.id, "permission": share.permission,
                "assessment_id": assessment.id, "security_status": "LIMITED" if limited else "PASSED"},
    )
    return {
        "activated": True, "source": source, "share_id": share.id,
        "document_uuid": doc.uuid, "permission": share.permission,
        "activated_at": now, "security_status": "LIMITED" if limited else "PASSED",
    }


@router.get("/shares/received", response_model=List[ShareOut])
def list_received_shares(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    share_repo = ShareRepository(db)
    doc_repo = DocumentRepository(db)
    user_repo = UserRepository(db)
    group_repo = GroupRepository(db)

    out = []

    # 1. Direct Shares
    direct_shares = share_repo.list_shares_for_user(current_user.id)
    for s in direct_shares:
        doc = doc_repo.get_by_id(s.document_id)
        if doc and not doc.is_deleted:
            owner = user_repo.get_by_id(doc.owner_id)
            out.append(ShareOut(
                id=s.id,
                document_id=doc.id,
                document_uuid=doc.uuid,
                document_name=doc.display_name or doc.original_name,
                owner_id=doc.owner_id,
                owner_username=owner.username if owner else "Unknown",
                target_user_id=current_user.id,
                target_username=current_user.username,
                target_email=current_user.email,
                permission=s.permission,
                source="direct",
                created_at=s.created_at,
                updated_at=s.updated_at,
                revoked_at=s.revoked_at,
                active=bool(s.active),
                share_key_required=bool(s.share_key_required),
                share_key_verified=(not bool(s.share_key_required)) or bool(s.share_key_verified_at),
                share_key_created_at=s.share_key_created_at,
                share_key_rotated_at=s.share_key_rotated_at,
                access_activated=PermissionService.is_share_activated(db, "direct", s.id, current_user.id, doc),
                **_shared_document_security_fields(db, doc)
            ))

    # 2. Group Shares
    group_ids = group_repo.get_user_group_ids(current_user.id)
    if group_ids:
        for gid in group_ids:
            grp = group_repo.get_group_by_id(gid)
            g_shares = share_repo.db.query(GroupDocumentShare).filter(
                GroupDocumentShare.group_id == gid,
                GroupDocumentShare.active == 1
            ).all()
            for gs in g_shares:
                doc = doc_repo.get_by_id(gs.document_id)
                if doc and not doc.is_deleted:
                    owner = user_repo.get_by_id(doc.owner_id)
                    out.append(ShareOut(
                        id=gs.id,
                        document_id=doc.id,
                        document_uuid=doc.uuid,
                        document_name=doc.display_name or doc.original_name,
                        owner_id=doc.owner_id,
                        owner_username=owner.username if owner else "Unknown",
                        target_user_id=current_user.id,
                        target_username=current_user.username,
                        target_email=current_user.email,
                        permission=gs.permission,
                        source="group",
                        group_name=grp.name if grp else "Group",
                        group_id=gs.group_id,
                        **_shared_document_security_fields(db, doc),
                        created_at=gs.created_at,
                        updated_at=gs.updated_at,
                        revoked_at=gs.revoked_at,
                        active=bool(gs.active),
                        access_activated=PermissionService.is_share_activated(db, "group", gs.id, current_user.id, doc)
                    ))

    return out

@router.get("/shares/sent", response_model=List[ShareOut])
def list_sent_shares(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List active direct and group shares created for documents owned by this user."""
    user_repo = UserRepository(db)
    group_repo = GroupRepository(db)
    out: List[ShareOut] = []

    direct_rows = (
        db.query(DocumentShare, DocumentModel)
        .join(DocumentModel, DocumentShare.document_id == DocumentModel.id)
        .filter(
            DocumentShare.owner_id == current_user.id,
            DocumentShare.active == 1,
            DocumentModel.owner_id == current_user.id,
            DocumentModel.is_deleted == 0,
        )
        .order_by(DocumentShare.updated_at.desc())
        .all()
    )
    for share, doc in direct_rows:
        target = user_repo.get_by_id(share.target_user_id)
        if not target:
            continue
        out.append(ShareOut(
            id=share.id, document_id=doc.id, document_uuid=doc.uuid,
            document_name=doc.display_name or doc.original_name,
            owner_id=current_user.id, owner_username=current_user.username,
            target_user_id=target.id, target_username=target.username, target_email=target.email,
            permission=share.permission, source="direct",
            created_at=share.created_at, updated_at=share.updated_at,
            revoked_at=share.revoked_at, active=bool(share.active),
            share_key_required=bool(share.share_key_required),
            share_key_verified=(not bool(share.share_key_required)) or bool(share.share_key_verified_at),
            share_key_created_at=share.share_key_created_at,
            share_key_rotated_at=share.share_key_rotated_at,
            **_shared_document_security_fields(db, doc),
        ))

    group_rows = (
        db.query(GroupDocumentShare, DocumentModel)
        .join(DocumentModel, GroupDocumentShare.document_id == DocumentModel.id)
        .filter(
            GroupDocumentShare.owner_id == current_user.id,
            GroupDocumentShare.active == 1,
            DocumentModel.owner_id == current_user.id,
            DocumentModel.is_deleted == 0,
        )
        .order_by(GroupDocumentShare.updated_at.desc())
        .all()
    )
    for share, doc in group_rows:
        group = group_repo.get_group_by_id(share.group_id)
        if not group:
            continue
        out.append(ShareOut(
            id=share.id, document_id=doc.id, document_uuid=doc.uuid,
            document_name=doc.display_name or doc.original_name,
            owner_id=current_user.id, owner_username=current_user.username,
            target_user_id=0, target_username=group.name, target_email="",
            permission=share.permission, source="group", group_name=group.name, group_id=group.id,
            created_at=share.created_at, updated_at=share.updated_at,
            revoked_at=share.revoked_at, active=bool(share.active),
            **_shared_document_security_fields(db, doc),
        ))

    out.sort(key=lambda item: item.updated_at or item.created_at, reverse=True)
    return out

