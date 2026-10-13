from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.database.repositories.group_repo import GroupRepository
from backend.schemas.access_lock_schema import (
    AccessLockEnableRequest, AccessLockUnlockRequest, AccessLockChangeRequest, AccessLockUnlockResponse
)
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.group import GroupDocumentShare
from backend.api.deps import get_current_user
from backend.security.password import PasswordManager
from backend.security.access_lock_limiter import access_lock_limiter
from backend.security.jwt_handler import JWTHandler
from backend.core.permission_service import PermissionService
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService

router = APIRouter(prefix="/documents", tags=["Access Lock"])

def _notify_shared_users_lock_event(
    db: Session,
    doc: DocumentModel,
    current_user: User,
    event_type: str,
    action_desc: str
):
    share_repo = ShareRepository(db)
    group_repo = GroupRepository(db)
    recipient_ids = set()

    # Direct recipients.
    for share in share_repo.list_active_direct_shares_for_document(doc.id):
        recipient_ids.add(share.target_user_id)

    # Group-derived recipients.
    for group_share in share_repo.list_group_shares_for_document(doc.id):
        members = group_repo.list_group_members(group_share.group_id)
        for member in members:
            recipient_ids.add(member.user_id)

    doc_title = doc.display_name or doc.original_name
    for recipient_id in recipient_ids:
        if recipient_id == current_user.id:
            continue

        NotificationService.notify(
            db,
            user_id=recipient_id,
            event_type=event_type,
            title="Document Access Lock Event",
            message=f"Access lock on document '{doc_title}' was {action_desc} by the owner.",
            document_id=doc.id
        )

@router.post("/{uuid}/access-lock/enable", status_code=status.HTTP_200_OK)
def enable_access_lock(
    uuid: str,
    data: AccessLockEnableRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can enable access lock")

    if data.access_key != data.confirm_access_key:
        raise HTTPException(status_code=400, detail="Access key and confirmation do not match")

    key_hash = PasswordManager.hash_password(data.access_key)
    doc.access_lock_hash = key_hash
    doc.is_access_locked = 1
    db.commit()

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="ACCESS_LOCK_ENABLED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent
    )

    _notify_shared_users_lock_event(db, doc, current_user, "ACCESS_LOCK_ENABLED", "enabled")
    return {"detail": "Document Access Lock enabled successfully."}


@router.post("/{uuid}/access-lock/unlock", response_model=AccessLockUnlockResponse)
def unlock_access_lock(
    uuid: str,
    data: AccessLockUnlockRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    # Pending recipients may verify the Access Lock before activating a share.
    # This does not authorize document reads; the permission service still blocks
    # detail/download/library access until the activation endpoint succeeds.
    if not doc or not (
        PermissionService.can_read(db, current_user, doc)
        or PermissionService.has_pending_share_access(db, current_user, doc)
    ):
        raise HTTPException(status_code=404, detail="Document not found")

    if not doc.is_access_locked or not doc.access_lock_hash:
        return AccessLockUnlockResponse(
            lock_token=JWTHandler.create_access_lock_token(
                doc.uuid,
                current_user.id,
                None
            ),
            message="Document is not locked"
        )

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Check rate limiter
    is_blocked, remaining_sec = access_lock_limiter.is_blocked(doc.id, current_user.id, ip_addr)
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many incorrect access key attempts. Temporarily locked for {remaining_sec} seconds."
        )

    # Verify key
    is_valid = PasswordManager.verify_password(data.access_key, doc.access_lock_hash)

    if not is_valid:
        count, threshold_exceeded = access_lock_limiter.record_failure(doc.id, current_user.id, ip_addr)

        AuditService.log(
            db, action="ACCESS_KEY_FAILURE", user_id=current_user.id,
            resource_type="document", resource_id=doc.uuid,
            ip_address=ip_addr, user_agent=user_agent, success=0
        )

        if threshold_exceeded:
            AuditService.log(
                db, action="ACCESS_KEY_FAILURE_THRESHOLD", user_id=current_user.id,
                resource_type="document", resource_id=doc.uuid,
                ip_address=ip_addr, user_agent=user_agent, success=0
            )

            doc_title = doc.display_name or doc.original_name
            NotificationService.notify(
                db,
                user_id=doc.owner_id,
                event_type="ACCESS_KEY_FAILURE_THRESHOLD",
                title="Access Key Failure Alert",
                message=f"Multiple failed access key attempts detected on document '{doc_title}' from IP {ip_addr or 'unknown'}.",
                document_id=doc.id
            )

        raise HTTPException(status_code=400, detail="Access key is incorrect.")

    # Verification successful
    access_lock_limiter.record_success(doc.id, current_user.id, ip_addr)

    AuditService.log(
        db, action="ACCESS_LOCK_UNLOCK_SUCCESS", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent
    )

    lock_token = JWTHandler.create_access_lock_token(doc.uuid, current_user.id, doc.access_lock_hash)
    return AccessLockUnlockResponse(lock_token=lock_token, expires_in=3600, message="Document unlocked successfully.")


@router.post("/{uuid}/access-lock/change", status_code=status.HTTP_200_OK)
def change_access_lock(
    uuid: str,
    data: AccessLockChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can change access lock")

    if data.new_key != data.confirm_new_key:
        raise HTTPException(status_code=400, detail="New access key and confirmation do not match")

    # If current key exists, verify if provided
    if doc.access_lock_hash and data.current_key:
        if not PasswordManager.verify_password(data.current_key, doc.access_lock_hash):
            raise HTTPException(status_code=400, detail="Current access key is incorrect")

    doc.access_lock_hash = PasswordManager.hash_password(data.new_key)
    doc.is_access_locked = 1
    db.commit()

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="ACCESS_LOCK_CHANGED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent
    )

    _notify_shared_users_lock_event(db, doc, current_user, "ACCESS_LOCK_CHANGED", "changed")
    return {"detail": "Document Access Lock key changed successfully."}


@router.delete("/{uuid}/access-lock", status_code=status.HTTP_200_OK)
def remove_access_lock(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can remove access lock")

    doc.access_lock_hash = None
    doc.is_access_locked = 0
    db.commit()

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="ACCESS_LOCK_REMOVED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent
    )

    _notify_shared_users_lock_event(db, doc, current_user, "ACCESS_LOCK_REMOVED", "removed")
    return {"detail": "Document Access Lock removed successfully."}
