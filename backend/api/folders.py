from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.folder_repo import FolderRepository
from backend.schemas.document_schema import FolderCreate, FolderOut
from backend.models.user import User
from backend.api.deps import get_current_user
from backend.core.audit_service import AuditService

router = APIRouter(prefix="/folders", tags=["Folders"])

@router.get("", response_model=List[FolderOut])
def list_folders(
    parent_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = FolderRepository(db)
    return repo.list_for_user(owner_id=current_user.id, parent_id=parent_id)

@router.post("", response_model=FolderOut, status_code=status.HTTP_201_CREATED)
def create_folder(
    data: FolderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = FolderRepository(db)
    folder = repo.create(name=data.name, owner_id=current_user.id, parent_id=data.parent_id)
    AuditService.log(db, action="FOLDER_CREATE", user_id=current_user.id, detail={"name": folder.name, "id": folder.id})
    return folder

@router.put("/{folder_id}", response_model=FolderOut)
def rename_folder(
    folder_id: int,
    data: FolderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = FolderRepository(db)
    folder = repo.rename(folder_id=folder_id, owner_id=current_user.id, new_name=data.name)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")
    AuditService.log(db, action="FOLDER_RENAME", user_id=current_user.id, detail={"id": folder_id, "new_name": data.name})
    return folder

@router.delete("/{folder_id}", status_code=status.HTTP_200_OK)
def delete_folder(
    folder_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = FolderRepository(db)
    ok = repo.delete(folder_id=folder_id, owner_id=current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="Folder not found")
    AuditService.log(db, action="FOLDER_DELETE", user_id=current_user.id, detail={"id": folder_id})
    return {"detail": "Folder deleted successfully"}
