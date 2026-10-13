from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.models.user import User
from backend.api.deps import get_current_user
from backend.core.explorer_service import ExplorerService

router = APIRouter(prefix="/explorer", tags=["Explorer"])

@router.get("/graph")
def get_relationship_graph(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns Power BI-Style node-edge relationship graph data strictly scoped
    to the authenticated user's authorized documents and entities.
    """
    return ExplorerService.build_user_graph(db, current_user, request.headers.get("X-Access-Lock-Token"))

@router.get("/history/{uuid}")
def get_document_history(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns chronological audit event history timeline for a selected document."""
    lock_token = request.headers.get("X-Access-Lock-Token")
    return ExplorerService.get_document_history_timeline(db, uuid, current_user, lock_token)
