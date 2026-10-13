from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.category_repo import CategoryRepository
from backend.schemas.document_schema import CategoryOut, CategoryCreate
from backend.models.user import User
from backend.api.deps import get_current_user
from backend.core.audit_service import AuditService

router = APIRouter(prefix="/categories", tags=["Categories"])

@router.get("", response_model=List[CategoryOut])
def list_categories(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = CategoryRepository(db)
    return repo.list_all(owner_id=current_user.id)

@router.post("", response_model=CategoryOut, status_code=status.HTTP_201_CREATED)
def create_category(
    data: CategoryCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = CategoryRepository(db)
    existing = repo.get_by_name(data.name, owner_id=current_user.id)
    if existing:
        return existing
    cat = repo.create_user_category(name=data.name, owner_id=current_user.id, description=data.description)
    AuditService.log(db, action="CATEGORY_CREATE", user_id=current_user.id, detail={"name": cat.name})
    return cat
