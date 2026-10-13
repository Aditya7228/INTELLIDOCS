import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request, Query, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc
from backend.database.connection import get_db
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.security_repo import SecurityRepository
from backend.schemas.document_schema import (
    DocumentOut, DocumentUpdate, DuplicateResultOut, DuplicateCandidateOut, VersionItemOut
)
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.security_assessment import SecurityAssessmentModel
from backend.api.deps import (
    get_current_user, document_service_instance, duplicate_service_instance, search_service_instance
)
from backend.security.path_guard import PathGuard
from backend.security.security_assessment_service import SecurityAssessmentService
from backend.security.quarantine_manager import QuarantineManager
from backend.core.audit_service import AuditService
from backend.core.permission_service import PermissionService
from backend.config import settings

router = APIRouter(prefix="/documents", tags=["Documents"])
path_guard = PathGuard()


async def _read_upload_limited(file: UploadFile) -> bytes:
    """Read at most the configured upload limit plus one byte, then reject oversized files."""
    max_bytes = max(1, int(settings.MAX_UPLOAD_SIZE_MB)) * 1024 * 1024
    file_bytes = await file.read(max_bytes + 1)
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"File exceeds the maximum upload size of {settings.MAX_UPLOAD_SIZE_MB} MB",
        )
    return file_bytes

DOCUMENT_SORT_FIELDS = {
    "uploaded_at": DocumentModel.uploaded_at,
    "original_name": DocumentModel.original_name,
    "display_name": DocumentModel.display_name,
    "size_bytes": DocumentModel.size_bytes,
    "file_type": DocumentModel.file_type,
    "category": DocumentModel.category,
    "sensitivity": DocumentModel.sensitivity,
}

@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    parent_version_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_bytes = await _read_upload_limited(file)
    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        # 1. FIRST SECURITY GATE: Untrusted Quarantine & Security Assessment Pipeline
        sec_service = SecurityAssessmentService()
        assessment = sec_service.run_assessment(
            db=db,
            filename=file.filename,
            content_type=file.content_type,
            file_bytes=file_bytes,
            owner_id=current_user.id,
            ip_address=ip_addr,
            user_agent=user_agent
        )

        sec_summary = {
            "quarantine_uuid": assessment.quarantine_uuid,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level,
            "confidence": assessment.confidence,
            "verdict": assessment.verdict,
            "data_sensitivity": assessment.data_sensitivity,
            "pii_detected": bool(assessment.pii_detected),
            "scanner_status": assessment.scanner_status,
            "check_states": json.loads(assessment.check_states_json),
            "findings": json.loads(assessment.findings_json),
            "why_explanations": json.loads(assessment.why_explanations_json),
            "potential_harms": json.loads(assessment.potential_harms_json),
            "recommended_action": assessment.recommended_action,
            "quarantine_status": assessment.quarantine_status
        }

        # 2. VERDICT GATE: If SUSPICIOUS or BLOCKED, keep quarantined and block normal library processing
        if assessment.verdict in ["SUSPICIOUS", "BLOCKED"]:
            return {
                "uuid": None,
                "original_name": assessment.original_name,
                "display_name": assessment.original_name,
                "file_type": assessment.file_type,
                "size_bytes": assessment.size_bytes,
                "category": "Quarantined",
                "sensitivity": assessment.data_sensitivity,
                "processing_status": assessment.verdict.lower(),
                "security_assessment": sec_summary,
                "message": f"Document blocked or quarantined due to security verdict: {assessment.verdict}"
            }

        # 3. VERDICT CLEARED / SAFE: Promote to normal IntelliDocs processing
        doc_record, dup_summary = document_service_instance.process_and_store_upload(
            db=db,
            filename=file.filename,
            content_type=file.content_type,
            file_bytes=file_bytes,
            owner_id=current_user.id,
            parent_version_id=parent_version_id,
            ip_address=ip_addr,
            user_agent=user_agent
        )

        # Link assessment to promoted document
        sec_repo = SecurityRepository(db)
        sec_repo.update_status(assessment.id, "PROMOTED", doc_record.id)

        return {
            "id": doc_record.id,  # INTELLIDOCS_UPLOAD_DOCUMENT_ID_V10
            "uuid": doc_record.uuid,
            "original_name": doc_record.original_name,
            "display_name": doc_record.display_name or doc_record.original_name,
            "file_type": doc_record.file_type,
            "size_bytes": doc_record.size_bytes,
            "category": doc_record.category,
            "sensitivity": doc_record.sensitivity,
            "version_number": doc_record.version_number,
            "processing_status": doc_record.processing_status,
            "duplicate_summary": dup_summary,
            "security_assessment": sec_summary,
            "user_permission": "OWNER"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload security gate processing failed: {str(e)}")


def _prepare_document_out(d: DocumentModel, perm: str, db: Session, current_user_id: Optional[int] = None, include_content: bool = True) -> DocumentOut:
    import json
    from backend.ai.summarizer import Summarizer
    from backend.core.document_view_service import effective_fields
    from backend.models.tag import Tag, document_tags

    user_id = int(current_user_id) if current_user_id is not None else int(d.owner_id)
    fields = effective_fields(db, d, user_id)
    display_name = fields.get("display_name") or d.original_name
    summary_value = d.summary
    topics_value = d.key_topics
    summary_stale = bool(summary_value) and Summarizer.summary_needs_refresh(summary_value, display_name)
    if include_content and d.extracted_text and (not summary_value or summary_stale or not topics_value):
        summarizer = Summarizer()
        if not summary_value or summary_stale:
            summary_value = summarizer.summarize_document(d.extracted_text, filename=display_name)
        if not topics_value:
            topics = summarizer.extract_key_topics(d.extracted_text, d.original_name, fields.get("category") or d.category)
            topics_value = json.dumps(topics)
        # Owners keep the shared canonical cache. Recipients get an ephemeral result
        # so a personalized filename never rewrites the owner's summary.
        if user_id == int(d.owner_id):
            d.summary = summary_value
            d.key_topics = topics_value
            db.commit()

    parsed_topics = []
    if topics_value:
        try:
            parsed_topics = json.loads(topics_value) if isinstance(topics_value, str) else topics_value
            if not isinstance(parsed_topics, list):
                parsed_topics = []
        except Exception:
            parsed_topics = []

    d_dict = {
        "id": d.id, "uuid": d.uuid, "original_name": d.original_name,
        "display_name": display_name, "file_type": d.file_type, "mime_type": d.mime_type,
        "size_bytes": d.size_bytes, "sha256_hash": d.sha256_hash, "page_count": d.page_count,
        "word_count": d.word_count, "extracted_text": d.extracted_text if include_content else None, "summary": summary_value if include_content else None,
        "key_topics": parsed_topics if include_content else [], "language": d.language, "category": fields.get("category"),
        "subcategory": d.subcategory, "folder_id": fields.get("folder_id"),
        "sensitivity": d.sensitivity, "has_ocr": d.has_ocr, "ocr_confidence": d.ocr_confidence,
        "version_group_id": d.version_group_id, "version_number": d.version_number,
        "parent_version_id": d.parent_version_id, "processing_status": d.processing_status,
        "owner_id": d.owner_id, "uploaded_at": d.uploaded_at,
        "is_access_locked": d.is_access_locked, "user_permission": perm,
        "tags": fields.get("tags", []),
    }
    return DocumentOut.model_validate(d_dict)


@router.get("", response_model=List[DocumentOut])
def list_documents(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    file_type: Optional[str] = None,
    category: Optional[str] = None,
    folder_id: Optional[int] = None,
    sensitivity: Optional[str] = None,
    tag_id: Optional[int] = None,
    sort_by: str = "uploaded_at",
    order: str = "desc",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
    if not accessible_ids and current_user.role != "admin":
        return []

    query = db.query(DocumentModel).filter(DocumentModel.is_deleted == 0)
    if current_user.role != "admin":
        query = query.filter(DocumentModel.id.in_(accessible_ids))

    if file_type:
        query = query.filter(DocumentModel.file_type == file_type)
    if category:
        from sqlalchemy import or_, and_
        from backend.models.user_document_preference import UserDocumentPreference
        query = query.filter(or_(
            DocumentModel.category == category,
            DocumentModel.id.in_(db.query(UserDocumentPreference.document_id).filter(
                UserDocumentPreference.user_id == current_user.id,
                UserDocumentPreference.category == category,
            )),
        ))
    if sensitivity:
        query = query.filter(DocumentModel.sensitivity == sensitivity)
    if folder_id is not None:
        from sqlalchemy import or_, and_
        from backend.models.user_document_preference import UserDocumentPreference
        query = query.filter(or_(
            and_(DocumentModel.owner_id == current_user.id, DocumentModel.folder_id == folder_id),
            DocumentModel.id.in_(db.query(UserDocumentPreference.document_id).filter(
                UserDocumentPreference.user_id == current_user.id,
                UserDocumentPreference.folder_id == folder_id,
            )),
        ))
    if tag_id:
        query = query.filter(DocumentModel.tags.any(id=tag_id))

    sort_col = DOCUMENT_SORT_FIELDS.get(sort_by, DocumentModel.uploaded_at)
    if order.lower() == "desc":
        query = query.order_by(desc(sort_col))
    else:
        query = query.order_by(asc(sort_col))

    offset = (page - 1) * limit
    docs = query.offset(offset).limit(limit).all()

    res = []
    lock_token = request.headers.get("X-Access-Lock-Token")
    for d in docs:
        perm = PermissionService.get_user_permission(db, current_user, d)
        include_content = PermissionService.check_access_lock(db, current_user, d, lock_token)
        res.append(_prepare_document_out(d, perm, db, current_user.id, include_content=include_content))

    return res


@router.post("/{uuid}/summary")
def regenerate_document_summary(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate a summary without allowing a recipient to rewrite the owner's cache."""
    doc = DocumentRepository(db).get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(status_code=403, detail="Access lock is enabled for this document. Please enter the access key to unlock.")
    if not doc.extracted_text or len(doc.extracted_text.strip()) < 30:
        raise HTTPException(status_code=422, detail="Not enough extractable text to generate an AI summary")

    from backend.ai.summarizer import Summarizer
    from backend.core.document_view_service import effective_fields
    fields = effective_fields(db, doc, current_user.id)
    summarizer = Summarizer()
    summary = summarizer.summarize_document(doc.extracted_text, filename=fields.get("display_name") or doc.display_name or doc.original_name)
    topics = summarizer.extract_key_topics(doc.extracted_text, doc.original_name, fields.get("category") or doc.category)
    if doc.owner_id == current_user.id:
        doc.summary = summary
        doc.key_topics = json.dumps(topics)
        db.commit()
    return {"uuid": doc.uuid, "summary": summary, "key_topics": topics}


@router.get("/{uuid}", response_model=DocumentOut)
def get_document_detail(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    perm = PermissionService.get_user_permission(db, current_user, doc)
    return _prepare_document_out(doc, perm, db, current_user.id)



@router.get("/{uuid}/download")
def download_document(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    lock_token = request.headers.get("X-Access-Lock-Token") or request.query_params.get("lock_token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    safe_path = path_guard.safe_upload_path(doc.stored_name)
    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="Physical file missing on server")

    AuditService.log(
        db, action="DOCUMENT_DOWNLOAD", user_id=current_user.id,
        resource_type="document", resource_id=uuid,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    from backend.core.document_view_service import effective_fields
    view_fields = effective_fields(db, doc, current_user.id)
    return FileResponse(
        path=str(safe_path),
        filename=view_fields.get("display_name") or doc.display_name or doc.original_name,
        media_type=doc.mime_type
    )


@router.get("/{uuid}/status")
def get_processing_status(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    return {
        "uuid": doc.uuid,
        "processing_status": doc.processing_status,
        "processing_error": doc.processing_error
    }


@router.put("/{uuid}", response_model=DocumentOut)
def update_document(
    uuid: str,
    data: DocumentUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.can_write(db, current_user, doc):
        raise HTTPException(status_code=403, detail="READ and APPEND users cannot modify document metadata")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    updates = data.model_dump(exclude_unset=True)
    if "category" in updates and updates.get("category") is not None:
        updates["category_source"] = "user_approved"
    updated = repo.update(doc.id, updates)

    if doc.extracted_text:
        search_service_instance.index_document(doc.id, doc.extracted_text)

    AuditService.log(db, action="DOCUMENT_UPDATE", user_id=current_user.id, resource_type="document", resource_id=uuid, detail=updates)
    perm = PermissionService.get_user_permission(db, current_user, updated)
    return _prepare_document_out(updated, perm, db, current_user.id)


@router.delete("/{uuid}", status_code=status.HTTP_200_OK)
def delete_document(
    uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    if not PermissionService.is_owner(db, current_user, doc):
        raise HTTPException(status_code=403, detail="Only the document owner can delete this document")

    repo.soft_delete(doc.id, current_user.id)
    search_service_instance.remove_document(doc.id)
    duplicate_service_instance.lsh_index.remove(doc.id)

    AuditService.log(db, action="DOCUMENT_DELETE", user_id=current_user.id, resource_type="document", resource_id=uuid)
    return {"detail": "Document successfully moved to Trash"}


@router.get("/{uuid}/related")
def get_related_documents(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    eb_list = duplicate_service_instance.analyze_all_candidates(db, doc, current_user.id, lock_token=lock_token)

    from backend.core.document_view_service import effective_fields
    related_items = []
    for eb in eb_list:
        other_doc = repo.get_by_uuid(eb.doc_b_uuid)
        if not other_doc or not PermissionService.can_read(db, current_user, other_doc):
            continue
        other_fields = effective_fields(db, other_doc, current_user.id)
        related_items.append({
            "document_uuid": eb.doc_b_uuid,
            "original_name": other_fields.get("display_name") or eb.doc_b_name,
            "relation_type": eb.relation_type,
            "confidence": eb.confidence,
            "scores": eb.scores,
            "detection_methods": eb.detection_methods,
            "supporting_evidence": eb.supporting_evidence
        })

    return {
        "document_uuid": doc.uuid,
        "total_related": len(related_items),
        "related_documents": related_items
    }


@router.get("/{uuid}/versions", response_model=List[VersionItemOut])
def list_document_versions(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    v_group_id = doc.version_group_id or str(doc.id)
    versions = db.query(DocumentModel).filter(
        DocumentModel.version_group_id == v_group_id,
        DocumentModel.is_deleted == 0
    ).order_by(DocumentModel.version_number.desc()).all()

    if not versions:
        versions = [doc]

    return [
        VersionItemOut(
            id=v.id,
            uuid=v.uuid,
            original_name=v.original_name,
            display_name=v.display_name,
            version_number=v.version_number or 1,
            uploaded_at=v.uploaded_at,
            size_bytes=v.size_bytes
        ) for v in versions
    ]


@router.post("/{uuid}/versions", status_code=status.HTTP_201_CREATED)
async def upload_new_version(
    uuid: str,
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    parent_doc = repo.get_by_uuid(uuid)
    if not parent_doc:
        raise HTTPException(status_code=404, detail="Parent document not found")

    if not PermissionService.can_append(db, current_user, parent_doc):
        raise HTTPException(status_code=403, detail="READ users cannot add new document versions")

    lock_token = request.headers.get("X-Access-Lock-Token")
    if not PermissionService.check_access_lock(db, current_user, parent_doc, lock_token):
        raise HTTPException(
            status_code=403,
            detail="Access lock is enabled for this document. Please enter the access key to unlock."
        )

    file_bytes = await _read_upload_limited(file)
    ip_addr = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        assessment = SecurityAssessmentService().run_assessment(
            db=db,
            filename=file.filename,
            content_type=file.content_type,
            file_bytes=file_bytes,
            owner_id=current_user.id,
            ip_address=ip_addr,
            user_agent=user_agent
        )

        security_assessment = {
            "quarantine_uuid": assessment.quarantine_uuid,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level,
            "confidence": assessment.confidence,
            "verdict": assessment.verdict,
            "data_sensitivity": assessment.data_sensitivity,
            "pii_detected": bool(assessment.pii_detected),
            "scanner_status": assessment.scanner_status,
            "check_states": json.loads(assessment.check_states_json),
            "findings": json.loads(assessment.findings_json),
            "why_explanations": json.loads(assessment.why_explanations_json),
            "potential_harms": json.loads(assessment.potential_harms_json),
            "recommended_action": assessment.recommended_action,
            "quarantine_status": assessment.quarantine_status,
        }

        if assessment.verdict in ["SUSPICIOUS", "BLOCKED"]:
            AuditService.log(
                db,
                action=f"DOCUMENT_VERSION_SECURITY_GATE_{assessment.verdict}",
                user_id=current_user.id,
                resource_type="document_version",
                resource_id=uuid,
                ip_address=ip_addr,
                user_agent=user_agent,
                detail={"quarantine_uuid": assessment.quarantine_uuid},
            )
            return {
                "uuid": None,
                "parent_version_id": parent_doc.id,
                "version_group_id": parent_doc.version_group_id,
                "version_number": None,
                "security_assessment": security_assessment,
                "message": f"New version blocked or quarantined due to security verdict: {assessment.verdict}",
            }

        new_doc, _ = document_service_instance.process_and_store_upload(
            db=db,
            filename=file.filename,
            content_type=file.content_type,
            file_bytes=file_bytes,
            owner_id=parent_doc.owner_id,
            parent_version_id=parent_doc.id,
            ip_address=ip_addr,
            user_agent=user_agent
        )

        SecurityRepository(db).update_status(assessment.id, "PROMOTED", new_doc.id)
        try:
            QuarantineManager().delete_quarantined_file(assessment.stored_quarantine_name)
        except Exception:
            pass

        AuditService.log(
            db,
            action="DOCUMENT_VERSION_SECURITY_GATE_PROMOTED",
            user_id=current_user.id,
            resource_type="document_version",
            resource_id=new_doc.uuid,
            ip_address=ip_addr,
            user_agent=user_agent,
            detail={
                "parent_uuid": uuid,
                "assessment_uuid": assessment.quarantine_uuid,
                "owner_id": parent_doc.owner_id,
            },
        )

        return {
            "uuid": new_doc.uuid,
            "version_number": new_doc.version_number,
            "parent_version_id": parent_doc.id,
            "version_group_id": new_doc.version_group_id,
            "security_assessment": security_assessment,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Version security gate processing failed: {str(exc)}"
        )


# ==========================================
# FILE SECURITY INTELLIGENCE ENDPOINTS


# ==========================================
# FILE SECURITY INTELLIGENCE ENDPOINTS
# ==========================================

@router.get("/security/status/{quarantine_uuid}")
def get_security_check_status(
    quarantine_uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)
    assessment = sec_repo.get_by_quarantine_uuid(quarantine_uuid)
    if not assessment:
        raise HTTPException(status_code=404, detail="Security assessment not found")

    if assessment.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied to private security assessment")

    return {
        "quarantine_uuid": assessment.quarantine_uuid,
        "original_name": assessment.original_name,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "confidence": assessment.confidence,
        "verdict": assessment.verdict,
        "scanner_status": assessment.scanner_status,
        "check_states": json.loads(assessment.check_states_json),
        "quarantine_status": assessment.quarantine_status
    }


@router.get("/security/report/{identifier}")
def get_security_report(
    identifier: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)

    # First try lookup by quarantine_uuid
    assessment = sec_repo.get_by_quarantine_uuid(identifier)

    # Fallback to lookup by document uuid
    if not assessment:
        doc_repo = DocumentRepository(db)
        doc = doc_repo.get_by_uuid(identifier)
        if doc:
            assessment = sec_repo.get_by_document_id(doc.id)

    if not assessment:
        raise HTTPException(status_code=404, detail="Security report not found for specified identifier")

    if assessment.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied to private security report")

    return {
        "id": assessment.id,
        "quarantine_uuid": assessment.quarantine_uuid,
        "document_id": assessment.document_id,
        "original_name": assessment.original_name,
        "file_type": assessment.file_type,
        "mime_type": assessment.mime_type,
        "size_bytes": assessment.size_bytes,
        "sha256_hash": assessment.sha256_hash,
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "confidence": assessment.confidence,
        "verdict": assessment.verdict,
        "data_sensitivity": assessment.data_sensitivity,
        "pii_detected": bool(assessment.pii_detected),
        "scanner_status": assessment.scanner_status,
        "check_states": json.loads(assessment.check_states_json),
        "findings": json.loads(assessment.findings_json),
        "why_explanations": json.loads(assessment.why_explanations_json),
        "potential_harms": json.loads(assessment.potential_harms_json),
        "recommended_action": assessment.recommended_action,
        "quarantine_status": assessment.quarantine_status,
        "created_at": assessment.created_at,
        "rescan_count": assessment.rescan_count
    }


@router.get("/quarantine/list")
def list_quarantined_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)
    items = sec_repo.list_quarantined_for_user(current_user.id)
    return [
        {
            "quarantine_uuid": item.quarantine_uuid,
            "original_name": item.original_name,
            "file_type": item.file_type,
            "size_bytes": item.size_bytes,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "confidence": item.confidence,
            "verdict": item.verdict,
            "quarantine_status": item.quarantine_status,
            "created_at": item.created_at,
            "recommended_action": item.recommended_action
        } for item in items
    ]


@router.post("/quarantine/{quarantine_uuid}/promote")
def promote_quarantined_document(
    quarantine_uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)
    assessment = sec_repo.get_by_quarantine_uuid(quarantine_uuid)
    if not assessment:
        raise HTTPException(status_code=404, detail="Quarantined document assessment not found")

    if assessment.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied to promote this quarantined document")

    # FORBIDDEN FOR MALICIOUS / BLOCKED FILES
    if assessment.verdict == "BLOCKED" or assessment.risk_level == "MALICIOUS":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot promote confirmed MALICIOUS file. File must remain isolated or be deleted."
        )

    # Read bytes from quarantine storage
    q_mgr = QuarantineManager()
    q_path = q_mgr.get_quarantine_path(assessment.stored_quarantine_name)
    if not q_path.exists():
        raise HTTPException(status_code=404, detail="Quarantined file bytes not found on disk")

    with open(q_path, "rb") as f:
        file_bytes = f.read()

    # Process into normal IntelliDocs library pipeline
    doc_record, dup_summary = document_service_instance.process_and_store_upload(
        db=db,
        filename=assessment.original_name,
        content_type=assessment.mime_type,
        file_bytes=file_bytes,
        owner_id=assessment.owner_id
    )

    # Update assessment record
    sec_repo.update_status(assessment.id, "PROMOTED", doc_record.id)

    # Remove temporary quarantine file
    q_mgr.delete_quarantined_file(assessment.stored_quarantine_name)

    AuditService.log(
        db,
        action="DOCUMENT_SECURITY_MANUAL_PROMOTED",
        user_id=current_user.id,
        resource_type="document",
        resource_id=doc_record.uuid,
        detail={"quarantine_uuid": quarantine_uuid, "original_name": assessment.original_name}
    )

    return {
        "status": "PROMOTED",
        "document_uuid": doc_record.uuid,
        "message": f"Document '{assessment.original_name}' promoted into library successfully."
    }


@router.post("/quarantine/{quarantine_uuid}/rescan")
def rescan_quarantined_document(
    quarantine_uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)
    assessment = sec_repo.get_by_quarantine_uuid(quarantine_uuid)
    if not assessment:
        raise HTTPException(status_code=404, detail="Quarantined document assessment not found")

    if assessment.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied to rescan this document")

    q_mgr = QuarantineManager()
    q_path = q_mgr.get_quarantine_path(assessment.stored_quarantine_name)
    if not q_path.exists():
        raise HTTPException(status_code=404, detail="Quarantined file bytes not found on disk")

    with open(q_path, "rb") as f:
        file_bytes = f.read()

    sec_service = SecurityAssessmentService()
    new_assessment = sec_service.run_assessment(
        db=db,
        filename=assessment.original_name,
        content_type=assessment.mime_type,
        file_bytes=file_bytes,
        owner_id=assessment.owner_id
    )
    new_assessment.rescan_count = assessment.rescan_count + 1
    db.commit()

    return {
        "status": "RESCANNED",
        "quarantine_uuid": new_assessment.quarantine_uuid,
        "verdict": new_assessment.verdict,
        "risk_score": new_assessment.risk_score,
        "risk_level": new_assessment.risk_level,
        "confidence": new_assessment.confidence
    }


@router.delete("/quarantine/{quarantine_uuid}")
def delete_quarantined_document(
    quarantine_uuid: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sec_repo = SecurityRepository(db)
    assessment = sec_repo.get_by_quarantine_uuid(quarantine_uuid)
    if not assessment:
        raise HTTPException(status_code=404, detail="Quarantined assessment not found")

    if assessment.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Permission denied to delete this quarantined item")

    q_mgr = QuarantineManager()
    q_mgr.delete_quarantined_file(assessment.stored_quarantine_name)

    sec_repo.update_status(assessment.id, "DELETED")

    AuditService.log(
        db,
        action="DOCUMENT_SECURITY_QUARANTINE_DELETED",
        user_id=current_user.id,
        resource_type="quarantine",
        resource_id=quarantine_uuid,
        detail={"original_name": assessment.original_name}
    )

    return {"status": "DELETED", "quarantine_uuid": quarantine_uuid}

