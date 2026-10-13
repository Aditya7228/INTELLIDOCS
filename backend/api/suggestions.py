from typing import List, Optional
import json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.suggestion_repo import SuggestionRepository
from backend.schemas.document_schema import SuggestionOut, SuggestionEditRequest, BulkSuggestionRequest, BulkAnalysisPlanOut
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.suggestion import DocumentSuggestion
from backend.core.permission_service import PermissionService
from backend.api.deps import get_current_user, search_service_instance, embedding_engine_instance
from backend.core.organization_service import OrganizationService

router = APIRouter(prefix="/suggestions", tags=["Suggestions"])
org_service = OrganizationService(embedding_engine=embedding_engine_instance)


def _to_suggestion_out(s):
    payload = {
        "id": s.id,
        "document_id": s.document_id,
        "suggestion_type": s.suggestion_type,
        "current_value": s.current_value,
        "suggested_value": s.suggested_value,
        "reason": s.reason,
        "confidence": s.confidence,
        "status": s.status,
        "created_at": s.created_at,
        "evidence": None,
    }
    if s.evidence:
        try:
            payload["evidence"] = json.loads(s.evidence) if isinstance(s.evidence, str) else s.evidence
        except Exception:
            payload["evidence"] = {"raw": str(s.evidence)}
    return SuggestionOut.model_validate(payload)

def _can_access_suggestion_document(db: Session, user: User, doc: DocumentModel, request: Request = None) -> bool:
    """Allow analysis/view only for activated shares that also pass Access Lock."""
    if not doc or getattr(doc, "is_deleted", 0):
        return False
    permission = PermissionService.get_user_permission(db, user, doc)
    if permission not in {"OWNER", "READ", "APPEND", "WRITE"}:
        return False
    tokens = PermissionService.parse_request_lock_tokens(request)
    token = PermissionService.resolve_access_lock_token(
        db, user, doc, lock_tokens=tokens,
        fallback_token=request.headers.get("X-Access-Lock-Token"),
    )
    return PermissionService.check_access_lock(db, user, doc, token)


def _suggestion_action_allowed(db: Session, user: User, suggestion_id: int, request: Request) -> bool:
    suggestion = db.query(DocumentSuggestion).filter(DocumentSuggestion.id == suggestion_id).first()
    if not suggestion:
        return False
    doc = db.query(DocumentModel).filter(DocumentModel.id == suggestion.document_id).first()
    return _can_access_suggestion_document(db, user, doc, request)


@router.get("", response_model=List[SuggestionOut])
def list_pending_suggestions(
    request: Request,
    document_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = SuggestionRepository(db)
    from sqlalchemy import or_, and_

    if document_id is not None:
        doc = db.query(DocumentModel).filter(
            DocumentModel.id == document_id, DocumentModel.is_deleted == 0
        ).first()
        if not _can_access_suggestion_document(db, current_user, doc, request):
            raise HTTPException(status_code=404, detail="Document not found or unauthorized")
        scope_user_id = None if doc.owner_id == current_user.id else current_user.id
        pending = db.query(DocumentSuggestion).filter(
            DocumentSuggestion.document_id == document_id,
            DocumentSuggestion.created_for_user_id == scope_user_id,
            DocumentSuggestion.status == "pending",
        ).order_by(DocumentSuggestion.created_at.desc(), DocumentSuggestion.id.desc()).all()
        # Recipient-facing AI recommendations are personal display/filing choices;
        # owner-global proposals are intentionally never surfaced or accepted here.
        if doc.owner_id != current_user.id:
            pending = [s for s in pending if s.suggestion_type in {"rename", "route_folder", "create_folder_group"}]
        return [_to_suggestion_out(s) for s in pending]

    accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
    if not accessible_ids:
        return []
    query = db.query(DocumentSuggestion).join(
        DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
    ).filter(
        DocumentModel.id.in_(accessible_ids),
        DocumentModel.is_deleted == 0,
        DocumentSuggestion.status == "pending",
        or_(
            and_(DocumentModel.owner_id == current_user.id, DocumentSuggestion.created_for_user_id.is_(None)),
            and_(DocumentModel.owner_id != current_user.id, DocumentSuggestion.created_for_user_id == current_user.id),
        ),
    ).order_by(DocumentSuggestion.created_at.desc(), DocumentSuggestion.id.desc()).all()
    safe_rows = []
    for suggestion in query:
        if suggestion.created_for_user_id == current_user.id and suggestion.suggestion_type not in {"rename", "route_folder", "create_folder_group"}:
            continue
        doc = db.query(DocumentModel).filter(DocumentModel.id == suggestion.document_id).first()
        if _can_access_suggestion_document(db, current_user, doc, request):
            safe_rows.append(suggestion)
    return [_to_suggestion_out(s) for s in safe_rows]

@router.post("/bulk-accept", response_model=List[SuggestionOut])
def bulk_accept_suggestions(
    data: BulkSuggestionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    safe_ids = [sid for sid in data.suggestion_ids if _suggestion_action_allowed(db, current_user, sid, request)]
    lock_tokens = PermissionService.parse_request_lock_tokens(request)
    accepted = []
    for sid in safe_ids:
        row = org_service.accept_suggestion(
            db, sid, current_user.id, search_service=search_service_instance,
            lock_tokens=lock_tokens,
        )
        if row:
            accepted.append(row)
    return [_to_suggestion_out(s) for s in accepted]

@router.post("/bulk-reject", response_model=List[SuggestionOut])
def bulk_reject_suggestions(
    data: BulkSuggestionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    safe_ids = [sid for sid in data.suggestion_ids if _suggestion_action_allowed(db, current_user, sid, request)]
    rejected = org_service.bulk_reject_suggestions(db, safe_ids, current_user.id)
    return [_to_suggestion_out(s) for s in rejected]

@router.post("/{suggestion_id}/accept", response_model=SuggestionOut)
def accept_suggestion(
    request: Request,
    suggestion_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not _suggestion_action_allowed(db, current_user, suggestion_id, request):
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    res = org_service.accept_suggestion(
        db, suggestion_id, current_user.id, search_service=search_service_instance,
        lock_tokens=PermissionService.parse_request_lock_tokens(request),
    )
    if not res:
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    return _to_suggestion_out(res)

@router.post("/{suggestion_id}/edit", response_model=SuggestionOut)
def edit_suggestion(
    suggestion_id: int,
    data: SuggestionEditRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not _suggestion_action_allowed(db, current_user, suggestion_id, request):
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    res = org_service.edit_suggestion(db, suggestion_id, data.custom_value, current_user.id, search_service=search_service_instance)
    if not res:
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    return _to_suggestion_out(res)

@router.post("/{suggestion_id}/reject", response_model=SuggestionOut)
def reject_suggestion(
    request: Request,
    suggestion_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not _suggestion_action_allowed(db, current_user, suggestion_id, request):
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    res = org_service.reject_suggestion(db, suggestion_id, current_user.id)
    if not res:
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    return _to_suggestion_out(res)


@router.post("/{suggestion_id}/keep", response_model=SuggestionOut)
def keep_suggestion(
    request: Request,
    suggestion_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not _suggestion_action_allowed(db, current_user, suggestion_id, request):
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    res = org_service.keep_suggestion(db, suggestion_id, current_user.id)
    if not res:
        raise HTTPException(status_code=404, detail="Pending suggestion not found or unauthorized")
    return _to_suggestion_out(res)


# INTELLIDOCS_V13_GROUP_ANALYSIS_ENDPOINT
@router.post("/analyze-groups", response_model=List[SuggestionOut])
def analyze_library_group_suggestions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Refresh owner groups plus recipient-private groups over safely accessible docs."""
    analyzer = getattr(org_service, "analyze_library_folder_groups", None)
    if not callable(analyzer):
        raise HTTPException(status_code=501, detail="Group-only analysis is not available in this project revision")
    previous_scope = db.info.get("suggestion_scope_user_id")
    lock_tokens = PermissionService.parse_request_lock_tokens(request)
    fallback_token = request.headers.get("X-Access-Lock-Token")
    try:
        # First preserve the normal owner-library group suggestions.
        db.info.pop("suggestion_scope_user_id", None)
        analyzer(db, current_user.id)
        # Then compute personal groups that may include activated, unlocked shared docs.
        db.info["suggestion_scope_user_id"] = current_user.id
        analyzer(
            db, current_user.id, lock_token=fallback_token,
            lock_tokens=lock_tokens,
        )
        accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
        from sqlalchemy import and_, or_
        pending = db.query(DocumentSuggestion).join(
            DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
        ).filter(
            DocumentModel.id.in_(accessible_ids or [-1]),
            DocumentModel.is_deleted == 0,
            DocumentSuggestion.suggestion_type == "create_folder_group",
            DocumentSuggestion.status == "pending",
            or_(
                and_(DocumentModel.owner_id == current_user.id, DocumentSuggestion.created_for_user_id.is_(None)),
                DocumentSuggestion.created_for_user_id == current_user.id,
            ),
        ).order_by(DocumentSuggestion.created_at.desc(), DocumentSuggestion.id.desc()).all()
        safe = []
        for row in pending:
            doc = db.query(DocumentModel).filter(DocumentModel.id == row.document_id).first()
            if _can_access_suggestion_document(db, current_user, doc, request):
                safe.append(_to_suggestion_out(row))
        return safe
    finally:
        if previous_scope is None:
            db.info.pop("suggestion_scope_user_id", None)
        else:
            db.info["suggestion_scope_user_id"] = previous_scope

@router.post("/analyze", response_model=BulkAnalysisPlanOut)
def analyze_suggestions(
    request: Request,
    document_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    previous_scope = db.info.get("suggestion_scope_user_id")
    lock_tokens = PermissionService.parse_request_lock_tokens(request)
    fallback_token = request.headers.get("X-Access-Lock-Token")
    generated_docs = []
    try:
        if document_id is not None:
            target_doc = db.query(DocumentModel).filter(
                DocumentModel.id == document_id, DocumentModel.is_deleted == 0
            ).first()
            if not _can_access_suggestion_document(db, current_user, target_doc, request):
                raise HTTPException(status_code=404, detail="Document not found or unauthorized")
            # Owner suggestions remain global. Activated recipients get their own
            # suggestion rows and personal folder/name recommendations.
            db.info["suggestion_scope_user_id"] = None if target_doc.owner_id == current_user.id else current_user.id
            org_service.generate_suggestions_for_document(db, target_doc)
            generated_docs = [target_doc]
        else:
            # Preserve the existing owner library planner, then add a recipient-scoped
            # single-document analysis for each activated shared document.
            db.info["suggestion_scope_user_id"] = None
            org_service.analyze_library_suggestions(db, current_user.id)
            accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
            shared_docs = db.query(DocumentModel).filter(
                DocumentModel.id.in_(accessible_ids or [-1]),
                DocumentModel.owner_id != current_user.id,
                DocumentModel.is_deleted == 0,
            ).all()
            generated_docs = db.query(DocumentModel).filter(
                DocumentModel.owner_id == current_user.id,
                DocumentModel.is_deleted == 0,
            ).all()
            for shared_doc in shared_docs:
                # Each received document needs its own independently verified unlock token.
                shared_token = PermissionService.resolve_access_lock_token(
                    db, current_user, shared_doc, lock_tokens=lock_tokens,
                    fallback_token=fallback_token,
                )
                if not PermissionService.check_access_lock(db, current_user, shared_doc, shared_token):
                    continue
                db.info["suggestion_scope_user_id"] = current_user.id
                org_service.generate_suggestions_for_document(db, shared_doc)
                generated_docs.append(shared_doc)

        category_counts = {}
        for doc in generated_docs:
            category = doc.category or "General"
            category_counts[category] = category_counts.get(category, 0) + 1

        repo = SuggestionRepository(db)
        if document_id is not None:
            scope_user_id = None if target_doc.owner_id == current_user.id else current_user.id
            pending = db.query(DocumentSuggestion).filter(
                DocumentSuggestion.document_id == document_id,
                DocumentSuggestion.created_for_user_id == scope_user_id,
                DocumentSuggestion.status == "pending",
            ).order_by(DocumentSuggestion.created_at.desc(), DocumentSuggestion.id.desc()).all()
            if target_doc.owner_id != current_user.id:
                pending = [s for s in pending if s.suggestion_type in {"rename", "route_folder", "create_folder_group"}]
        else:
            from sqlalchemy import or_, and_
            pending = db.query(DocumentSuggestion).join(
                DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
            ).filter(
                DocumentModel.id.in_(PermissionService.list_accessible_document_ids(db, current_user.id) or [-1]),
                DocumentModel.is_deleted == 0, DocumentSuggestion.status == "pending",
                or_(
                    and_(DocumentModel.owner_id == current_user.id, DocumentSuggestion.created_for_user_id.is_(None)),
                    and_(DocumentModel.owner_id != current_user.id, DocumentSuggestion.created_for_user_id == current_user.id),
                )
            ).order_by(DocumentSuggestion.created_at.desc(), DocumentSuggestion.id.desc()).all()
            pending = [s for s in pending if s.created_for_user_id != current_user.id or s.suggestion_type in {"rename", "route_folder", "create_folder_group"}]
        return BulkAnalysisPlanOut(
            analyzed_count=len(generated_docs),
            category_counts=category_counts,
            suggestions=[_to_suggestion_out(s) for s in pending]
        )
    finally:
        if previous_scope is None:
            db.info.pop("suggestion_scope_user_id", None)
        else:
            db.info["suggestion_scope_user_id"] = previous_scope

