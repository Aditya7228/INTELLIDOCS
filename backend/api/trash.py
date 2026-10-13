from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document import DocumentModel
from backend.schemas.document_schema import DocumentOut
from backend.models.user import User
from backend.api.deps import get_current_user, path_guard
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService

router = APIRouter(prefix="/trash", tags=["Trash"])

@router.get("", response_model=List[DocumentOut])
def list_trashed_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    items = db.query(DocumentModel).filter(
        DocumentModel.owner_id == current_user.id,
        DocumentModel.is_deleted == 1
    ).order_by(DocumentModel.deleted_at.desc()).all()
    return items

@router.post("/{uuid}/restore", status_code=status.HTTP_200_OK)
def restore_document(
    uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(DocumentModel).filter(
        DocumentModel.uuid == uuid,
        DocumentModel.owner_id == current_user.id,
        DocumentModel.is_deleted == 1
    ).first()

    if not doc:
        raise HTTPException(status_code=404, detail="Trashed document not found")

    doc.is_deleted = 0
    doc.deleted_at = None
    doc.deleted_by = None
    db.commit()

    AuditService.log(db, action="DOCUMENT_RESTORE", user_id=current_user.id, resource_type="document", resource_id=uuid)
    NotificationService.notify(db, user_id=current_user.id, event_type="DOCUMENT_RESTORED", title="Document Restored", message=f"Restored '{doc.original_name}' from Trash.", document_id=doc.id)
    return {"detail": "Document successfully restored from Trash"}

@router.delete("/{uuid}/purge", status_code=status.HTTP_200_OK)
def purge_document(
    uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    doc = db.query(DocumentModel).filter(
        DocumentModel.uuid == uuid,
        DocumentModel.owner_id == current_user.id,
        DocumentModel.is_deleted == 1
    ).first()

    if not doc:
        raise HTTPException(status_code=404, detail="Trashed document not found")

    # Delete physical stored file safely
    safe_path = path_guard.safe_upload_path(doc.stored_name)
    if safe_path.exists():
        try:
            safe_path.unlink()
        except Exception:
            pass

    db.delete(doc)
    db.commit()

    AuditService.log(db, action="DOCUMENT_PURGE", user_id=current_user.id, resource_type="document", resource_id=uuid)
    return {"detail": "Document permanently purged"}
