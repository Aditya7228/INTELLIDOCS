from typing import List, Tuple
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.tag_repo import TagRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.schemas.tag_schema import TagCreate, TagOut, TagAssign, TagUpdate
from backend.models.user import User
from backend.api.deps import get_current_user
from backend.core.audit_service import AuditService
from backend.core.permission_service import PermissionService

router = APIRouter(prefix="/tags", tags=["Tags"])

@router.get("", response_model=List[TagOut])
def list_tags(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = TagRepository(db)

    # User-facing tag counts only include documents accessible to this user.
    if current_user.role == "admin":
        raw_tags = repo.list_all()
    else:
        accessible_ids = PermissionService.list_accessible_document_ids(
            db, current_user.id
        )
        raw_tags = repo.list_all(accessible_ids)
    results = []
    for tag_obj, count in raw_tags:
        results.append(TagOut(
            id=tag_obj.id,
            name=tag_obj.name,
            color=tag_obj.color,
            document_count=count,
            created_by=tag_obj.created_by
        ))
    return results

@router.post("", response_model=TagOut, status_code=status.HTTP_201_CREATED)
def create_tag(
    data: TagCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = TagRepository(db)
    existing = repo.get_by_name(data.name)
    if existing:
        return TagOut(id=existing.id, name=existing.name, color=existing.color, document_count=0, created_by=existing.created_by)

    tag = repo.create(name=data.name, color=data.color or "#6366f1", created_by=current_user.id)
    return TagOut(id=tag.id, name=tag.name, color=tag.color, document_count=0, created_by=tag.created_by)

@router.post("/documents/{uuid}/tags", status_code=status.HTTP_200_OK)
def assign_tags(
    uuid: str,
    data: TagAssign,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc or (doc.owner_id != current_user.id and current_user.role != "admin"):
        raise HTTPException(status_code=404, detail="Document not found")

    tag_repo = TagRepository(db)
    tag_repo.assign_tags_to_doc(doc.id, data.tag_ids, current_user.id)
    AuditService.log(db, action="TAG_ASSIGN", user_id=current_user.id, resource_type="document", resource_id=uuid, detail={"tag_ids": data.tag_ids})
    return {"detail": "Tags assigned successfully"}

@router.delete("/documents/{uuid}/tags/{tag_id}", status_code=status.HTTP_200_OK)
def remove_tag(
    uuid: str,
    tag_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc_repo = DocumentRepository(db)
    doc = doc_repo.get_by_uuid(uuid)
    if not doc or (doc.owner_id != current_user.id and current_user.role != "admin"):
        raise HTTPException(status_code=404, detail="Document not found")

    tag_repo = TagRepository(db)
    tag_repo.remove_tag_from_doc(doc.id, tag_id)
    AuditService.log(db, action="TAG_REMOVE", user_id=current_user.id, resource_type="document", resource_id=uuid, detail={"tag_id": tag_id})
    return {"detail": "Tag removed successfully"}


@router.put("/{tag_id}", response_model=TagOut)
def update_tag(
    tag_id: int,
    data: TagUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    name = data.name.strip() if data.name is not None else None
    if name is not None and not name:
        raise HTTPException(status_code=400, detail="Tag name cannot be empty")
    repo = TagRepository(db)
    if name is not None:
        existing = repo.get_by_name(name)
        if existing and existing.id != tag_id:
            raise HTTPException(status_code=400, detail=f"Tag '{name}' already exists")
    tag = repo.update_owned(tag_id, current_user.id, name=name, color=data.color)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found or you do not own it")
    AuditService.log(db, action="TAG_UPDATE", user_id=current_user.id, detail={"tag_id": tag_id, "name": tag.name})
    count = repo.list_all(PermissionService.list_accessible_document_ids(db,current_user.id)).copy()
    doc_count = next((c for t,c in count if t.id == tag.id), 0)
    return TagOut(id=tag.id, name=tag.name, color=tag.color, document_count=doc_count, created_by=tag.created_by)

@router.delete("/{tag_id}")
def delete_tag(
    tag_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = TagRepository(db)
    if not repo.delete_owned(tag_id, current_user.id):
        raise HTTPException(status_code=409, detail="Tag cannot be deleted. It may be protected, not owned by you, or used by another user's document.")
    AuditService.log(db, action="TAG_DELETE", user_id=current_user.id, detail={"tag_id": tag_id})
    return {"detail": "Tag deleted successfully"}
