from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.group_repo import GroupRepository
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.schemas.group_schema import (
    GroupCreateRequest, GroupUpdateRequest, GroupMemberAddRequest,
    GroupShareRequest, GroupOut, GroupMemberOut
)
from backend.schemas.share_schema import ShareOut
from backend.models.user import User
from backend.models.group import GroupModel, GroupMemberModel, GroupDocumentShare
from backend.api.deps import get_current_user
from backend.core.permission_service import PermissionService
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService

router = APIRouter(prefix="/groups", tags=["Groups"])

def _format_group(db: Session, group: GroupModel, user_repo: UserRepository, group_repo: GroupRepository) -> GroupOut:
    owner = user_repo.get_by_id(group.owner_id)
    members_raw = group_repo.list_group_members(group.id)
    members_out = []

    for m in members_raw:
        u = user_repo.get_by_id(m.user_id)
        if u:
            members_out.append(GroupMemberOut(
                user_id=u.id,
                username=u.username,
                email=u.email,
                role=m.role,
                joined_at=m.created_at
            ))

    return GroupOut(
        id=group.id,
        name=group.name,
        owner_id=group.owner_id,
        owner_username=owner.username if owner else "Unknown",
        member_count=len(members_out),
        members=members_out,
        created_at=group.created_at,
        updated_at=group.updated_at
    )

@router.post("", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
def create_group(
    data: GroupCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)

    # Initial member count check (owner + initial targets <= 7)
    initial_usernames = data.member_usernames or []
    if len(initial_usernames) + 1 > 7:
        raise HTTPException(status_code=400, detail="Groups can contain up to 7 members.")

    group = group_repo.create_group(name=data.name, owner_id=current_user.id)

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="GROUP_CREATED", user_id=current_user.id,
        resource_type="group", resource_id=str(group.id),
        ip_address=ip_addr, user_agent=user_agent,
        detail={"name": group.name}
    )

    # Add initial members
    for target_str in initial_usernames:
        u = user_repo.get_by_username(target_str) or user_repo.get_by_email(target_str)
        if u and u.id != current_user.id:
            group_repo.add_member(group.id, u.id, role="member")
            NotificationService.notify(
                db,
                user_id=u.id,
                event_type="GROUP_MEMBER_ADDED",
                title="Added to Group",
                message=f"{current_user.username} added you to group '{group.name}'"
            )

    return _format_group(db, group, user_repo, group_repo)


@router.get("", response_model=List[GroupOut])
def list_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)
    groups = group_repo.list_user_groups(current_user.id)
    return [_format_group(db, g, user_repo, group_repo) for g in groups]


@router.get("/{group_id}", response_model=GroupOut)
def get_group_detail(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)
    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    member = group_repo.get_member(group_id, current_user.id)
    if not member and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    return _format_group(db, group, user_repo, group_repo)


@router.put("/{group_id}", response_model=GroupOut)
def rename_group(
    group_id: int,
    data: GroupUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)
    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the group owner can rename the group")

    updated = group_repo.rename_group(group_id, data.name)
    AuditService.log(
        db, action="GROUP_RENAMED", user_id=current_user.id,
        resource_type="group", resource_id=str(group_id),
        detail={"new_name": data.name}
    )
    return _format_group(db, updated, user_repo, group_repo)


@router.delete("/{group_id}", status_code=status.HTTP_200_OK)
def delete_group(
    group_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    share_repo = ShareRepository(db)
    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the group owner can delete the group")

    # Revoke group document shares safely
    group_shares = db.query(GroupDocumentShare).filter(GroupDocumentShare.group_id == group_id, GroupDocumentShare.active == 1).all()
    for gs in group_shares:
        share_repo.revoke_group_share(gs.id)

    group_name = group.name
    group_repo.delete_group(group_id)

    AuditService.log(
        db, action="GROUP_DELETED", user_id=current_user.id,
        resource_type="group", resource_id=str(group_id),
        detail={"name": group_name}
    )

    return {"detail": f"Group '{group_name}' has been deleted."}


@router.post("/{group_id}/members", response_model=GroupOut)
def add_group_member(
    group_id: int,
    data: GroupMemberAddRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)
    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    if group.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the group owner can add members")

    current_count = group_repo.count_members(group_id)
    if current_count >= 7:
        raise HTTPException(status_code=400, detail="Groups can contain up to 7 members.")

    target = user_repo.get_by_username(data.username_or_email) or user_repo.get_by_email(data.username_or_email)
    if not target:
        raise HTTPException(status_code=400, detail=f"User '{data.username_or_email}' not found")

    existing_m = group_repo.get_member(group_id, target.id)
    if existing_m:
        raise HTTPException(status_code=400, detail=f"User '{target.username}' is already in this group")

    group_repo.add_member(group_id, target.id, role="member")

    AuditService.log(
        db, action="GROUP_MEMBER_ADDED", user_id=current_user.id,
        resource_type="group", resource_id=str(group_id),
        detail={"added_username": target.username}
    )

    NotificationService.notify(
        db,
        user_id=target.id,
        event_type="GROUP_MEMBER_ADDED",
        title="Added to Group",
        message=f"{current_user.username} added you to group '{group.name}'"
    )

    return _format_group(db, group, user_repo, group_repo)


@router.delete("/{group_id}/members/{target_user_id}", response_model=GroupOut)
def remove_group_member(
    group_id: int,
    target_user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    user_repo = UserRepository(db)
    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Allowed if current_user is group owner OR target_user_id is self (leaving group)
    if group.owner_id != current_user.id and target_user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the group owner can remove other members")

    target = user_repo.get_by_id(target_user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Member not found")

    group_repo.remove_member(group_id, target_user_id)

    # Note: Removing a user from the group revokes their group-derived document access,
    # BUT their direct share (if any) remains completely untouched as per Part 3 requirement!

    AuditService.log(
        db, action="GROUP_MEMBER_REMOVED", user_id=current_user.id,
        resource_type="group", resource_id=str(group_id),
        detail={"removed_username": target.username}
    )

    NotificationService.notify(
        db,
        user_id=target.id,
        event_type="GROUP_MEMBER_REMOVED",
        title="Removed from Group",
        message=f"You were removed from group '{group.name}'"
    )

    return _format_group(db, group, user_repo, group_repo)


@router.post("/{group_id}/shares", response_model=ShareOut, status_code=status.HTTP_201_CREATED)
def share_document_with_group(
    group_id: int,
    data: GroupShareRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    doc_repo = DocumentRepository(db)
    share_repo = ShareRepository(db)

    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    doc = doc_repo.get_by_uuid(data.document_uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if group.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only the group owner can share documents with this group")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can share this document with a group")

    if not PermissionService.is_document_security_cleared(db, doc):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Document sharing is disabled until its security assessment is SAFE and PROMOTED.",
        )

    group_share = share_repo.create_group_share(
        document_id=doc.id,
        group_id=group.id,
        owner_id=current_user.id,
        permission=data.permission
    )

    AuditService.log(
        db, action="GROUP_DOCUMENT_SHARED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        detail={"group_name": group.name, "permission": data.permission}
    )

    doc_title = doc.display_name or doc.original_name
    members = group_repo.list_group_members(group.id)
    for m in members:
        if m.user_id != current_user.id:
            NotificationService.notify(
                db,
                user_id=m.user_id,
                event_type="GROUP_DOCUMENT_SHARED",
                title="Document Shared With Group",
                message=f"{current_user.username} shared '{doc_title}' with your group '{group.name}' ({data.permission} permission)",
                document_id=doc.id
            )

    return ShareOut(
        id=group_share.id,
        document_id=doc.id,
        document_uuid=doc.uuid,
        document_name=doc_title,
        owner_id=current_user.id,
        owner_username=current_user.username,
        target_user_id=0,
        target_username=group.name,
        target_email=f"group_{group.id}@intellidocs.local",
        permission=group_share.permission,
        source="group",
        group_name=group.name,
        group_id=group.id,
        created_at=group_share.created_at,
        updated_at=group_share.updated_at,
        revoked_at=group_share.revoked_at,
        active=bool(group_share.active)
    )


@router.put("/{group_id}/shares/{share_id}", response_model=ShareOut)
def update_group_share_permission(
    group_id: int,
    share_id: int,
    data: GroupShareRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    doc_repo = DocumentRepository(db)
    share_repo = ShareRepository(db)

    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    gs = share_repo.get_group_share_by_id(share_id)
    if not gs or gs.group_id != group_id:
        raise HTTPException(status_code=404, detail="Group share not found")

    doc = doc_repo.get_by_id(gs.document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can change group share permission")

    updated = share_repo.update_group_share_permission(share_id, doc.id, data.permission)
    if not updated:
        raise HTTPException(status_code=404, detail="Active group share not found")

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="GROUP_SHARE_PERMISSION_CHANGED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent,
        detail={"group_name": group.name, "new_permission": data.permission}
    )

    doc_title = doc.display_name or doc.original_name
    members = group_repo.list_group_members(group.id)
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
        id=updated.id,
        document_id=doc.id,
        document_uuid=doc.uuid,
        document_name=doc_title,
        owner_id=doc.owner_id,
        owner_username=current_user.username,
        target_user_id=0,
        target_username=group.name,
        target_email=f"group_{group.id}@intellidocs.local",
        permission=updated.permission,
        source="group",
        group_name=group.name,
        group_id=group.id,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
        revoked_at=updated.revoked_at,
        active=bool(updated.active)
    )


@router.delete("/{group_id}/shares/{share_id}", status_code=status.HTTP_200_OK)
def revoke_group_share(
    group_id: int,
    share_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group_repo = GroupRepository(db)
    doc_repo = DocumentRepository(db)
    share_repo = ShareRepository(db)

    group = group_repo.get_group_by_id(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    gs = share_repo.get_group_share_by_id(share_id)
    if not gs or gs.group_id != group_id:
        raise HTTPException(status_code=404, detail="Group share not found")

    doc = doc_repo.get_by_id(gs.document_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can revoke group share")

    revoked = share_repo.revoke_group_share(share_id, doc.id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Active group share not found or already revoked")

    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    AuditService.log(
        db, action="GROUP_DOCUMENT_SHARE_REVOKED", user_id=current_user.id,
        resource_type="document", resource_id=doc.uuid,
        ip_address=ip_addr, user_agent=user_agent,
        detail={"group_name": group.name}
    )

    doc_title = doc.display_name or doc.original_name
    members = group_repo.list_group_members(group.id)
    for m in members:
        if m.user_id != current_user.id:
            NotificationService.notify(
                db,
                user_id=m.user_id,
                event_type="GROUP_ACCESS_REVOKED",
                title="Group Document Access Revoked",
                message=f"{current_user.username} revoked access to '{doc_title}' for group '{group.name}'",
                document_id=doc.id
            )

    return {"detail": f"Access to '{doc_title}' for group '{group.name}' has been revoked successfully."}
