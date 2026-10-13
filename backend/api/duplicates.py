import difflib
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from backend.database.connection import get_db
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document import DocumentModel
from backend.schemas.document_schema import DuplicateResultOut, DuplicateCandidateOut, DuplicateDecisionRequest
from backend.models.user import User
from backend.api.deps import get_current_user, duplicate_service_instance
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService
from backend.core.duplicate_policy import (
    DUPLICATE_NEAR_THRESHOLD, classify_duplicate_evidence,
)
from backend.core.duplicate_service import normalize_text_for_comparison
from backend.utils.perceptual_hash import dhash_similarity
from backend.core.permission_service import PermissionService

router = APIRouter(prefix="/duplicates", tags=["Duplicates"])


def _fallback_pair_classification(doc_a, doc_b):
    """Classify a visible document pair from strict, inexpensive evidence only.

    The alert endpoint uses this only when candidate discovery omitted a pair.
    Dense semantic similarity is intentionally excluded: related documents are
    not duplicates. This helper never persists global relation state.
    """
    text_a = getattr(doc_a, "extracted_text", None) or ""
    text_b = getattr(doc_b, "extracted_text", None) or ""
    norm_a = normalize_text_for_comparison(text_a)
    norm_b = normalize_text_for_comparison(text_b)

    if norm_a and norm_b:
        if norm_a == norm_b:
            text_score = 1.0
        else:
            text_score = difflib.SequenceMatcher(
                None, norm_a[:2000], norm_b[:2000]
            ).ratio()
    else:
        text_score = 0.0

    sha_a = getattr(doc_a, "sha256_hash", None)
    sha_b = getattr(doc_b, "sha256_hash", None)
    sha_match = bool(sha_a and sha_b and sha_a == sha_b)

    visual_score = 0.0
    hash_a = getattr(doc_a, "perceptual_hash", None)
    hash_b = getattr(doc_b, "perceptual_hash", None)
    if hash_a and hash_b:
        try:
            visual_score = float(dhash_similarity(hash_a, hash_b))
        except Exception:
            visual_score = 0.0

    scores = {
        "sha256_match": 1.0 if sha_match else 0.0,
        "normalized_content_sim": float(text_score),
        "ocr_text_sim": float(text_score)
        if (getattr(doc_a, "has_ocr", 0) or getattr(doc_b, "has_ocr", 0))
        else 0.0,
        "visual_perceptual_sim": float(visual_score),
    }
    classification = classify_duplicate_evidence(scores)
    if not classification.actionable:
        return None

    methods = []
    evidence = []
    if sha_match:
        methods.append("SHA-256 Digest")
        evidence.append("Byte-identical SHA-256 hash")
    if text_score >= DUPLICATE_NEAR_THRESHOLD:
        methods.append("Normalized Text Matching")
        evidence.append(
            f"Text content matches with {round(text_score * 100, 1)}% similarity"
        )
    if visual_score >= DUPLICATE_NEAR_THRESHOLD:
        methods.append("Perceptual dHash")
        evidence.append(
            f"Visual perceptual dHash similarity of {round(visual_score * 100, 1)}%"
        )

    return {
        "relation_type": classification.relation_type,
        "confidence": float(classification.confidence),
        "detection_methods": methods,
        "supporting_evidence": evidence,
        "scores": scores,
    }


@router.get("/alerts")
def get_duplicate_alerts(
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return actionable duplicate/near-duplicate candidates across the user's library.

    This powers dashboard badges/alerts so duplicate intelligence is visible without
    requiring the user to manually inspect each document first.
    """
    repo = DocumentRepository(db)
    lock_tokens = PermissionService.parse_request_lock_tokens(request)
    fallback_token = request.headers.get("X-Access-Lock-Token") if request is not None else None
    # Inspect the entire active library; the previous 100-document cap hid older files.
    accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
    docs = (
        db.query(DocumentModel)
        .filter(DocumentModel.id.in_(accessible_ids or [-1]), DocumentModel.is_deleted == 0)
        .order_by(DocumentModel.id.asc())
        .all()
    )

    docs = [
        d for d in docs
        if PermissionService.check_access_lock(
            db, current_user, d,
            PermissionService.resolve_access_lock_token(
                db, current_user, d, lock_tokens=lock_tokens,
                fallback_token=fallback_token,
            ),
        )
    ]
    visible_ids = {d.id for d in docs}
    from backend.core.document_view_service import effective_fields

    pairs = {}
    actionable = {
        "exact_duplicate",
        "content_duplicate",
        "near_duplicate",
        "visual_similarity",
        "possible_version",
    }

    # Keep the alert layer aligned with DuplicateService's evidence threshold.
    duplicate_threshold = DUPLICATE_NEAR_THRESHOLD

    for doc in docs:
        evidence_list = duplicate_service_instance.analyze_all_candidates(
            db, doc, current_user.id,
            lock_token=PermissionService.resolve_access_lock_token(
                db, current_user, doc, lock_tokens=lock_tokens,
                fallback_token=fallback_token,
            ),
            lock_tokens=lock_tokens,
        )
        for eb in evidence_list:
            if eb.relation_type not in actionable:
                continue
            if eb.confidence <= duplicate_threshold and eb.relation_type != "exact_duplicate":
                continue
            other = repo.get_by_uuid(eb.doc_b_uuid)
            if not other or other.id not in visible_ids:
                continue
            pair_key = tuple(sorted((doc.id, other.id)))
            existing = pairs.get(pair_key)
            if existing is None or eb.confidence > existing["confidence"]:
                doc_fields = effective_fields(db, doc, current_user.id)
                other_fields = effective_fields(db, other, current_user.id)
                pairs[pair_key] = {
                    "document_uuid": doc.uuid,
                    "document_name": doc_fields.get("display_name") or doc.original_name,
                    "candidate_uuid": eb.doc_b_uuid,
                    "candidate_name": other_fields.get("display_name") or eb.doc_b_name,
                    "relation_type": eb.relation_type,
                    "confidence": eb.confidence,
                    "detection_methods": eb.detection_methods,
                    "supporting_evidence": eb.supporting_evidence,
                    "scores": eb.scores,
                }

    # Reliability fallback: candidate discovery is an optimization, not a source
    # of truth. Re-check pairs that were not emitted by the discovery pipeline
    # using strict content/hash/visual evidence, but only among documents already
    # proven accessible and unlocked above. This also handles shared documents
    # whose owners differ; no cross-user relation is persisted here.
    # Bound this fallback to pairs involving the 100 newest visible documents.
    # The primary candidate pipeline still scans the full library; this sweep is
    # a resilience layer and must not make the dashboard's fallback unbounded.
    recent_docs = docs[-100:]
    for doc in recent_docs:
        for other in docs:
            if other.id == doc.id:
                continue
            pair_key = tuple(sorted((doc.id, other.id)))
            if pair_key in pairs:
                continue
            try:
                fallback = _fallback_pair_classification(doc, other)
            except Exception:
                continue
            if not fallback:
                continue
            relation_type = fallback["relation_type"]
            confidence = fallback["confidence"]
            if relation_type not in {"exact_duplicate", "near_duplicate"}:
                continue
            if confidence <= duplicate_threshold and relation_type != "exact_duplicate":
                continue
            doc_fields = effective_fields(db, doc, current_user.id)
            other_fields = effective_fields(db, other, current_user.id)
            # Keep a stable ascending-ID orientation in the response payload.
            left, right = (doc, other) if doc.id < other.id else (other, doc)
            left_fields = doc_fields if left.id == doc.id else other_fields
            right_fields = other_fields if right.id == other.id else doc_fields
            pairs[pair_key] = {
                "document_uuid": left.uuid,
                "document_name": left_fields.get("display_name") or left.original_name,
                "candidate_uuid": right.uuid,
                "candidate_name": right_fields.get("display_name") or right.original_name,
                "relation_type": relation_type,
                "confidence": confidence,
                "detection_methods": fallback["detection_methods"],
                "supporting_evidence": fallback["supporting_evidence"],
                "scores": fallback["scores"],
            }

    # Since the API returns at most 100 alerts, put pairs involving newer document
    # IDs first. This prevents fresh alerts from being buried behind stale rows
    # from previous test runs or older library activity.
    ordered_pairs = sorted(
        pairs.items(),
        key=lambda item: (item[0][1], item[0][0], item[1]["confidence"]),
        reverse=True,
    )
    return {
        "alert_count": len(ordered_pairs),
        "alerts": [alert for _pair_key, alert in ordered_pairs[:100]],
    }

@router.get("/{uuid}", response_model=DuplicateResultOut)
def get_document_duplicates(
    uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    doc = repo.get_by_uuid(uuid)
    if not doc or not PermissionService.can_read(db, current_user, doc):
        raise HTTPException(status_code=404, detail="Document not found")
    lock_tokens = PermissionService.parse_request_lock_tokens(request)
    target_lock_token = PermissionService.resolve_access_lock_token(
        db, current_user, doc, lock_tokens=lock_tokens,
        fallback_token=request.headers.get("X-Access-Lock-Token"),
    )
    if not PermissionService.check_access_lock(db, current_user, doc, target_lock_token):
        raise HTTPException(status_code=403, detail="Access lock is enabled for this document. Please unlock it from Received by Me before checking duplicates.")

    eb_list = duplicate_service_instance.analyze_all_candidates(
        db, doc, current_user.id, lock_token=target_lock_token,
        lock_tokens=lock_tokens,
    )

    from backend.core.document_view_service import effective_fields
    candidates = []
    for eb in eb_list:
        other = repo.get_by_uuid(eb.doc_b_uuid)
        if not other or not PermissionService.can_read(db, current_user, other):
            continue
        view = effective_fields(db, other, current_user.id)
        candidates.append(DuplicateCandidateOut(
            document_uuid=eb.doc_b_uuid,
            original_name=view.get("display_name") or eb.doc_b_name,
            relation_type=eb.relation_type,
            confidence=eb.confidence,
            scores=eb.scores,
            detection_methods=eb.detection_methods,
            supporting_evidence=eb.supporting_evidence
        ))

    return DuplicateResultOut(
        document_uuid=doc.uuid,
        has_duplicates=len(candidates) > 0,
        candidate_count=len(candidates),
        candidates=candidates
    )

@router.post("/decide", status_code=status.HTTP_200_OK)
def handle_duplicate_decision(
    data: DuplicateDecisionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = DocumentRepository(db)
    new_doc = repo.get_by_uuid(data.new_doc_uuid)
    existing_doc = repo.get_by_uuid(data.existing_doc_uuid)

    if (
        not new_doc
        or not existing_doc
        or new_doc.owner_id != current_user.id
        or existing_doc.owner_id != current_user.id
    ):
        # Do not let a user reference another account's document UUID in a decision.
        raise HTTPException(status_code=404, detail="Document record not found")

    if data.action == "keep_both":
        AuditService.log(db, action="DUPLICATE_DECISION_KEEP_BOTH", user_id=current_user.id, detail={"new_uuid": new_doc.uuid, "existing_uuid": existing_doc.uuid})
        return {"detail": "Decision recorded: Both documents retained separately."}

    elif data.action == "trash_new":
        repo.soft_delete(new_doc.id, current_user.id)
        AuditService.log(db, action="DUPLICATE_DECISION_TRASH_NEW", user_id=current_user.id, detail={"trashed_uuid": new_doc.uuid})
        NotificationService.notify(db, user_id=current_user.id, event_type="DOCUMENT_TRASHED", title="Document Trashed", message=f"Moved candidate '{new_doc.original_name}' to Trash.", document_id=new_doc.id)
        return {"detail": "Decision recorded: New candidate moved to Trash."}

    elif data.action == "review":
        return {"detail": "Side-by-side review mode activated.", "new_doc_uuid": new_doc.uuid, "existing_doc_uuid": existing_doc.uuid}

    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: '{data.action}'")


# INTELLIDOCS_V19_PERSISTENT_SUGGESTIONS_DUPLICATE_REPAIR
