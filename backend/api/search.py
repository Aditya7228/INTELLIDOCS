from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.schemas.search_schema import SearchResultOut, AutocompleteOut, SearchHit
from backend.models.user import User
from backend.api.deps import get_current_user, search_service_instance
from backend.core.audit_service import AuditService
from backend.core.permission_service import PermissionService

router = APIRouter(prefix="/search", tags=["Search"])

@router.get("", response_model=SearchResultOut)
def keyword_search(
    request: Request,
    q: str = Query(..., min_length=1),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    file_type: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    hits, total = search_service_instance.keyword_search(
        db=db,
        query=q,
        current_user_id=current_user.id,
        page=page,
        limit=limit,
        file_type=file_type,
        category=category,
        lock_token=request.headers.get("X-Access-Lock-Token")
    )

    from backend.schemas.document_schema import DocumentOut
    from backend.core.permission_service import PermissionService
    from backend.core.document_view_service import effective_fields
    formatted_results = []
    for h in hits:
        doc = h["document"]
        payload = DocumentOut.model_validate(doc).model_dump()
        payload.update(effective_fields(db, doc, current_user.id))
        payload["user_permission"] = PermissionService.get_user_permission(db, current_user, doc)
        formatted_results.append(SearchHit(
            document=DocumentOut.model_validate(payload), score=h["score"], snippet=h["snippet"]
        ))

    AuditService.log(db, action="SEARCH_KEYWORD", user_id=current_user.id, detail={"query": q, "total_hits": total})

    return SearchResultOut(
        query=q,
        total=total,
        page=page,
        results=formatted_results
    )

@router.get("/suggest", response_model=AutocompleteOut)
def autocomplete_suggest(
    request: Request,
    prefix: str = Query(..., min_length=2),
    limit: int = Query(10, ge=1, le=20),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
    from backend.models.document import DocumentModel
    accessible_docs = db.query(DocumentModel).filter(DocumentModel.id.in_(accessible_ids or [-1]), DocumentModel.is_deleted == 0).all()
    lock_token = request.headers.get("X-Access-Lock-Token")
    accessible_ids = {d.id for d in accessible_docs if PermissionService.check_access_lock(db, current_user, d, lock_token)}
    suggestions = search_service_instance.autocomplete(
        prefix=prefix, limit=limit, accessible_document_ids=accessible_ids
    )
    return AutocompleteOut(prefix=prefix, suggestions=suggestions)
