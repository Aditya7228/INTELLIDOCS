import re
import json
import uuid
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.models.document import DocumentModel
from backend.models.suggestion import DocumentSuggestion
from backend.models.folder import FolderModel
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.suggestion_repo import SuggestionRepository
from backend.database.repositories.category_repo import CategoryRepository
from backend.database.repositories.folder_repo import FolderRepository
from backend.database.repositories.tag_repo import TagRepository
from backend.core.audit_service import AuditService
from backend.core.notification_service import NotificationService
from backend.core.categorization_service import CategorizationService
from backend.core.sensitivity_service import SensitivityService

FILENAME_EXPANSIONS = {
    "clg": "College",
    "univ": "University",
    "fee": "Fee",
    "fees": "Fees",
    "rec": "Receipt",
    "rcpt": "Receipt",
    "assign": "Assignment",
    "hw": "Homework",
    "cert": "Certificate",
    "res": "Resume",
    "cv": "CV",
    "inv": "Invoice",
    "stmt": "Statement",
    "rpt": "Report",
    "proj": "Project",
    "dsa": "DSA",
    "id": "ID"
}

GENERIC_STOP_TAGS = {"document", "image", "file", "png", "jpg", "jpeg", "pdf", "txt", "docx", "general", "page", "the", "and"}

def _can_manage_shared_document_suggestion(db, doc, user_id: int, suggestion_type: str, suggestion=None) -> bool:
    """Keep owner-global suggestions private; recipient rows affect only their own view."""
    if not doc or getattr(doc, "is_deleted", 0) or not suggestion:
        return False
    scoped_user = getattr(suggestion, "created_for_user_id", None)
    if doc.owner_id == user_id:
        return scoped_user is None
    if scoped_user != user_id or suggestion_type not in {"rename", "route_folder", "categorize"}:
        return False
    from backend.models.user import User
    from backend.core.permission_service import PermissionService
    user = db.query(User).filter(User.id == user_id).first()
    # Personal presentation/folder preferences do not mutate the source document,
    # so any fully activated READ+ share may review them.
    return bool(user and PermissionService.can_read(db, user, doc))


class OrganizationService:
    def __init__(self, embedding_engine=None):
        self.embedding_engine = embedding_engine

    def _save_or_update_suggestion(
        self,
        db: Session,
        s_repo: SuggestionRepository,
        doc: DocumentModel,
        suggestion_type: str,
        current_val: Optional[str],
        suggested_val: str,
        reason: str,
        confidence: float,
        evidence: dict
    ) -> Optional[DocumentSuggestion]:
        import json
        existing = s_repo.get_existing_for_document(doc.id, suggestion_type)
        if existing:
            if existing.status == "pending":
                existing.current_value = current_val
                existing.suggested_value = suggested_val
                existing.reason = reason
                existing.confidence = confidence
                existing.evidence = json.dumps(evidence) if evidence else None
                db.commit()
                db.refresh(existing)
                return existing
            elif existing.status in ("accepted", "rejected", "kept") and existing.suggested_value == suggested_val:
                return None

        return s_repo.create(
            document_id=doc.id,
            suggestion_type=suggestion_type,
            current_value=current_val,
            suggested_value=suggested_val,
            reason=reason,
            confidence=confidence,
            evidence=evidence
        )

    @staticmethod
    def normalize_sensitivity(value: str) -> str:
        raw = (value or "").strip().lower()
        return {
            "public": "public",
            "internal": "internal",
            "pii": "pii",
            "confidential": "pii",
            "restricted": "pii",
            "private": "pii",
        }.get(raw, "")

    @staticmethod
    def sensitivity_display(value: str) -> str:
        normalized = OrganizationService.normalize_sensitivity(value)
        return {
            "public": "Public",
            "internal": "Internal",
            "pii": "Confidential",
        }.get(normalized, "Needs Review")

    @staticmethod
    def sensitivity_recommendation(text: str, sensitivity: str, pii_types: List[str]) -> dict:
        normalized = OrganizationService.normalize_sensitivity(sensitivity)
        found = sorted({str(x) for x in (pii_types or []) if str(x).strip()})
        if normalized == "pii":
            critical = {"AADHAAR", "PAN", "CREDIT_CARD", "EMAIL", "PHONE_IN"}
            critical_hits = [x for x in found if x in critical]
            confidence = 0.95 if critical_hits else 0.88
            reason = "Sensitive personal information indicators were detected"
            if critical_hits:
                reason += ": " + ", ".join(critical_hits[:4]) + "."
            else:
                reason += "."
            status = "PENDING"
        elif normalized == "internal":
            confidence = 0.78
            reason = "The document contains internal/entity information and should not be treated as fully public."
            status = "PENDING"
        else:
            confidence = 0.60
            reason = "No supported high-risk PII indicators were detected in the analyzed text."
            status = "NEEDS_REVIEW"
        return {
            "sensitivity": normalized or "public",
            "display_level": OrganizationService.sensitivity_display(normalized),
            "pii_types": found[:8],
            "confidence": confidence,
            "status_label": status,
            "reason": reason,
        }
    def generate_suggestions_for_document(self, db: Session, doc: DocumentModel) -> List[DocumentSuggestion]:
        """
        Multi-signal analysis of document content, metadata, filename, and context.
        Generates pending AI organization suggestions.
        Does NOT alter document records directly. All actions require human approval.
        """
        s_repo = SuggestionRepository(db)
        suggestions = []

        text = doc.extracted_text or ""
        text_lower = text.lower()
        orig_name = doc.original_name
        ext = orig_name.split(".")[-1] if "." in orig_name else doc.file_type

        # Analyze PII signals
        sensitivity, pii_types = SensitivityService().analyze(text)

        # AI_SENSITIVITY_RECOMMENDATION_V1
        sensitivity_evidence = self.sensitivity_recommendation(
            text=text, sensitivity=sensitivity, pii_types=pii_types
        )
        if sensitivity_evidence["sensitivity"] != "public":
            s = self._save_or_update_suggestion(
                db=db,
                s_repo=s_repo,
                doc=doc,
                suggestion_type="sensitivity",
                current_val=doc.sensitivity or "public",
                suggested_val=sensitivity_evidence["sensitivity"],
                reason=sensitivity_evidence["reason"],
                confidence=sensitivity_evidence["confidence"],
                evidence=sensitivity_evidence,
            )
            if s:
                suggestions.append(s)

        # 1. Multi-Signal Category Suggestion
        cat_service = CategorizationService(embedding_engine=self.embedding_engine)
        suggested_cat, cat_conf, cat_source, cat_evidence = cat_service.categorize_multi_signal(
            text=text,
            filename=orig_name,
            file_type=doc.file_type,
            pii_types=pii_types,
            ocr_confidence=doc.ocr_confidence
        )

        category_label = doc.category if (doc.category and doc.category_source == "user_approved") else suggested_cat

        if (not doc.category or doc.category == "General" or doc.category_source != "user_approved") and suggested_cat != doc.category:
            status_lbl = "PENDING" if cat_conf >= 0.70 else "NEEDS_REVIEW"
            cat_evidence["status_label"] = status_lbl
            s = self._save_or_update_suggestion(
                db=db,
                s_repo=s_repo,
                doc=doc,
                suggestion_type="categorize",
                current_val=doc.category or "General",
                suggested_val=suggested_cat,
                reason=cat_evidence.get("reason", f"Suggested category '{suggested_cat}' based on multi-signal analysis"),
                confidence=cat_conf,
                evidence=cat_evidence
            )
            if s:
                suggestions.append(s)

        # 2. Contextual Filename Suggestion
        suggested_filename = self._generate_contextual_filename(orig_name, text, category_label, ext)
        current_display = doc.display_name or orig_name

        if suggested_filename and suggested_filename.lower() != current_display.lower() and suggested_filename.lower() != orig_name.lower():
            rename_conf = 0.91 if cat_conf >= 0.70 else 0.75
            rename_evidence = {
                "detected_title": suggested_filename,
                "original_filename": orig_name,
                "category": category_label,
                "status_label": "PENDING" if rename_conf >= 0.70 else "NEEDS_REVIEW"
            }
            s = self._save_or_update_suggestion(
                db=db,
                s_repo=s_repo,
                doc=doc,
                suggestion_type="rename",
                current_val=current_display,
                suggested_val=suggested_filename,
                reason=f"Suggested clean display filename '{suggested_filename}' derived from filename terms ('{orig_name}') and OCR content",
                confidence=rename_conf,
                evidence=rename_evidence
            )
            if s:
                suggestions.append(s)

        # 3. Contextual Tag Suggestions
        suggested_tags = self._infer_contextual_tags(orig_name, text_lower, category_label, pii_types)
        if suggested_tags:
            tag_str = ", ".join(suggested_tags)
            tag_evidence = {
                "tags": suggested_tags,
                "category": category_label,
                "status_label": "PENDING"
            }
            s = self._save_or_update_suggestion(
                db=db,
                s_repo=s_repo,
                doc=doc,
                suggestion_type="add_tag",
                current_val="",
                suggested_val=tag_str,
                reason=f"Suggested tags '{tag_str}' based on document topics, filename terms, and category",
                confidence=0.85,
                evidence=tag_evidence
            )
            if s:
                suggestions.append(s)

        if suggestions:
            NotificationService.notify(
                db,
                user_id=doc.owner_id,
                event_type="SUGGESTION_READY",
                title="Organization Suggestions Available",
                message=f"IntelliDocs generated {len(suggestions)} organization suggestion(s) for '{doc.original_name}'",
                document_id=doc.id
            )

        return suggestions

    def _generate_contextual_filename(self, orig_name: str, text: str, category: str, ext: str) -> Optional[str]:
        fn_clean = re.sub(r"\.[^/.]+$", "", orig_name)
        tokens = [t.strip() for t in re.split(r"[_\s\.-]+", fn_clean) if t.strip()]

        expanded = []
        for t in tokens:
            t_low = t.lower()
            if t_low in FILENAME_EXPANSIONS:
                expanded.append(FILENAME_EXPANSIONS[t_low])
            elif len(t) > 1:
                expanded.append(t.capitalize())

        # Look for additional title keywords in text/OCR
        text_title_words = []
        if text:
            first_lines = [line.strip() for line in text.split("\n") if len(line.strip()) > 3][:4]
            for line in first_lines:
                clean_line = re.sub(r"[^\w\s-]", "", line)
                w_list = [w for w in clean_line.split() if w.lower() not in GENERIC_STOP_TAGS and len(w) > 2]
                if 1 <= len(w_list) <= 5:
                    for w in w_list:
                        if w.lower() not in [x.lower() for x in expanded]:
                            text_title_words.append(w.capitalize())
                    break

        combined_words = expanded + text_title_words[:3]
        if not combined_words:
            return None

        # Build clean title
        title_str = "_".join(combined_words[:5])
        if category and category != "General" and category.lower() not in title_str.lower():
            title_str = f"{category.replace('/', '_')}_{title_str}"

        candidate_name = f"{title_str}.{ext}"
        candidate_name = re.sub(r"[^\w\.-]", "_", candidate_name)
        candidate_name = re.sub(r"_+", "_", candidate_name)

        if candidate_name.lower() == orig_name.lower():
            return None

        return candidate_name

    def _infer_contextual_tags(self, filename: str, text_lower: str, category: str, pii_types: Optional[List[str]] = None) -> List[str]:
        tags = set()
        fn_clean = re.sub(r"\.[^/.]+$", "", filename).lower()
        fn_tokens = re.split(r"[_\s\.-]+", fn_clean)

        for token in fn_tokens:
            if token in FILENAME_EXPANSIONS:
                tags.add(FILENAME_EXPANSIONS[token].lower())
            elif len(token) > 2 and token not in GENERIC_STOP_TAGS:
                tags.add(token.lower())

        # OCR Keyword concepts
        if "college" in text_lower or "university" in text_lower:
            tags.add("college")
        if "fee" in text_lower or "fees" in text_lower or "tuition" in text_lower:
            tags.add("fees")
        if "receipt" in text_lower:
            tags.add("receipt")
        if "semester" in text_lower:
            tags.add("semester")
        if "python" in text_lower:
            tags.add("python")
        if "dsa" in text_lower or "algorithm" in text_lower or "data structure" in text_lower:
            tags.add("dsa")
        if "assignment" in text_lower:
            tags.add("assignment")
        if "certificate" in text_lower:
            tags.add("certificate")
        if "resume" in text_lower or "cv" in text_lower:
            tags.add("resume")
        if "education" in text_lower:
            tags.add("education")

        # Category and topic tags are separate concepts.
        generic_categories = {
            "academic", "assignment", "certificate", "resume/cv", "identity",
            "financial", "legal", "professional", "project", "personal", "general"
        }
        if category and category.lower().strip() not in generic_categories:
            tags.add(category.lower().replace("/", "_"))

        filtered_tags = [t for t in tags if t not in GENERIC_STOP_TAGS and len(t) > 1]
        return filtered_tags[:5]

    def accept_suggestion(self, db: Session, suggestion_id: int, user_id: int, search_service=None) -> Optional[DocumentSuggestion]:
        """Apply user-approved suggestion to logical database record."""
        s_repo = SuggestionRepository(db)
        suggestion = s_repo.get_by_id(suggestion_id)
        if not suggestion or suggestion.status != "pending":
            return None

        doc_repo = DocumentRepository(db)
        doc = doc_repo.get_by_id(suggestion.document_id)
        if not _can_manage_shared_document_suggestion(db, doc, user_id, suggestion.suggestion_type, suggestion):
            return None

        if suggestion.suggestion_type == "rename":
            doc.display_name = suggestion.suggested_value
            AuditService.log(db, action="SUGGESTION_ACCEPT_RENAME", user_id=user_id, resource_type="document", resource_id=doc.uuid, detail={"new_display_name": suggestion.suggested_value})
            NotificationService.notify(db, user_id=user_id, event_type="DOCUMENT_RENAMED", title="Document Renamed", message=f"Document renamed to '{suggestion.suggested_value}'", document_id=doc.id)

        elif suggestion.suggestion_type == "categorize":
            doc.category = suggestion.suggested_value
            doc.category_source = "user_approved"
            AuditService.log(db, action="SUGGESTION_ACCEPT_CATEGORIZE", user_id=user_id, resource_type="document", resource_id=doc.uuid, detail={"category": suggestion.suggested_value})
            NotificationService.notify(db, user_id=user_id, event_type="DOCUMENT_CATEGORIZED", title="Document Categorized", message=f"Document categorized as '{suggestion.suggested_value}'", document_id=doc.id)

        elif suggestion.suggestion_type == "add_tag":
            tag_repo = TagRepository(db)
            tag_names = [t.strip() for t in suggestion.suggested_value.split(",") if t.strip()]
            tag_ids = []
            for tname in tag_names:
                tag_obj = tag_repo.get_by_name(tname)
                if not tag_obj:
                    tag_obj = tag_repo.create(name=tname, created_by=user_id)
                tag_ids.append(tag_obj.id)
            if tag_ids:
                tag_repo.assign_tags_to_doc(doc.id, tag_ids, user_id)

        elif suggestion.suggestion_type == "sensitivity":
            normalized = self.normalize_sensitivity(suggestion.suggested_value)
            if not normalized:
                return None
            doc.sensitivity = normalized
            AuditService.log(
                db,
                action="SUGGESTION_ACCEPT_SENSITIVITY",
                user_id=user_id,
                resource_type="document",
                resource_id=doc.uuid,
                detail={"sensitivity": normalized},
            )
            NotificationService.notify(
                db,
                user_id=user_id,
                event_type="DOCUMENT_SENSITIVITY_UPDATED",
                title="Document Sensitivity Updated",
                message=f"Document sensitivity set to '{self.sensitivity_display(normalized)}'",
                document_id=doc.id,
            )

        elif suggestion.suggestion_type == "move_folder":
            try:
                folder_id = int(suggestion.suggested_value)
                doc.folder_id = folder_id
                NotificationService.notify(db, user_id=user_id, event_type="DOCUMENT_MOVED", title="Document Moved", message="Document moved to folder", document_id=doc.id)
            except ValueError:
                pass

        elif suggestion.suggestion_type == "create_folder_group":
            evidence_data = {}
            if suggestion.evidence:
                try:
                    import json
                    if isinstance(suggestion.evidence, str):
                        evidence_data = json.loads(suggestion.evidence)
                    elif isinstance(suggestion.evidence, dict):
                        evidence_data = suggestion.evidence
                except Exception:
                    pass

            doc_ids = evidence_data.get("document_ids", [suggestion.document_id])
            folder_name = suggestion.suggested_value.strip()

            folder_repo = FolderRepository(db)
            folder = db.query(FolderModel).filter(
                FolderModel.name == folder_name,
                FolderModel.owner_id == user_id
            ).first()

            if not folder:
                folder = folder_repo.create(name=folder_name, owner_id=user_id)

            approved_tags = [
                str(tag).strip()
                for tag in evidence_data.get("suggested_tags", [])
                if str(tag).strip()
            ]

            for did in doc_ids:
                d = doc_repo.get_by_id(did)
                if d and d.owner_id == user_id:
                    d.folder_id = folder.id
                    if evidence_data.get("suggested_category"):
                        d.category = evidence_data.get("suggested_category")
                        d.category_source = "user_approved"

                    if approved_tags:
                        tag_repo = TagRepository(db)
                        tag_ids = []
                        for tname in approved_tags[:3]:
                            tag_obj = tag_repo.get_by_name(tname)
                            if not tag_obj:
                                tag_obj = tag_repo.create(name=tname, created_by=user_id)
                            tag_ids.append(tag_obj.id)
                        if tag_ids:
                            tag_repo.assign_tags_to_doc(d.id, tag_ids, user_id)

            AuditService.log(
                db, action="SUGGESTION_ACCEPT_ORGANIZATION", user_id=user_id,
                resource_type="folder", resource_id=str(folder.id),
                detail={"folder_name": folder_name, "document_count": len(doc_ids)}
            )

            NotificationService.notify(
                db, user_id=user_id, event_type="AI_ORGANIZATION_SUGGESTION_READY",
                title="Folder Group Applied",
                message=f"Applied AI folder organization '{folder_name}' for {len(doc_ids)} document(s)"
            )

        db.commit()
        s_repo.resolve(suggestion_id, status="accepted", resolved_by=user_id)

        if search_service and doc.extracted_text:
            search_service.index_document(doc.id, doc.extracted_text)

        return suggestion

    def create_organization_group_suggestion(
        self,
        db: Session,
        owner_id: int,
        folder_name: str,
        doc_ids: List[int],
        reason: str,
        confidence: float = 0.91,
        suggested_category: Optional[str] = None,
        suggested_tags: Optional[List[str]] = None
    ) -> Optional[DocumentSuggestion]:
        if not doc_ids:
            return None

        doc_repo = DocumentRepository(db)
        docs = [doc_repo.get_by_id(did) for did in doc_ids if doc_repo.get_by_id(did)]
        if not docs:
            return None

        primary_doc = docs[0]
        s_repo = SuggestionRepository(db)

        status_label = "PENDING" if confidence >= 0.70 else "NEEDS_REVIEW"

        normalized_doc_ids = sorted({d.id for d in docs})
        evidence = {
            "document_ids": normalized_doc_ids,
            "document_names": [d.original_name for d in docs],
            "suggested_category": suggested_category or primary_doc.category or "General",
            "suggested_tags": suggested_tags or [],
            "status_label": status_label
        }

        existing = s_repo.find_group_suggestion(owner_id, folder_name, normalized_doc_ids)
        if existing:
            if existing.status == "pending":
                existing.reason = reason
                existing.confidence = confidence
                existing.evidence = json.dumps(evidence)
                db.commit()
                db.refresh(existing)
                return existing
            # Do not recreate an already-resolved identical recommendation.
            return None

        s = s_repo.create(
            document_id=primary_doc.id,
            suggestion_type="create_folder_group",
            current_value="Unorganized",
            suggested_value=folder_name,
            reason=reason,
            confidence=confidence,
            evidence=evidence
        )

        NotificationService.notify(
            db,
            user_id=owner_id,
            event_type="AI_ORGANIZATION_SUGGESTION_READY",
            title="AI Organization Suggestion Ready",
            message=f"Suggested folder '{folder_name}' for {len(docs)} document(s) ({reason})",
            document_id=primary_doc.id
        )

        return s

    def edit_suggestion(self, db: Session, suggestion_id: int, custom_value: str, user_id: int, search_service=None) -> Optional[DocumentSuggestion]:
        s_repo = SuggestionRepository(db)
        suggestion = s_repo.get_by_id(suggestion_id)
        if not suggestion or suggestion.status != "pending":
            return None

        doc = DocumentRepository(db).get_by_id(suggestion.document_id)
        if not _can_manage_shared_document_suggestion(db, doc, user_id, suggestion.suggestion_type, suggestion):
            return None
        suggestion.suggested_value = custom_value.strip()
        db.commit()
        return self.accept_suggestion(db, suggestion_id, user_id, search_service)

    def keep_suggestion(self, db: Session, suggestion_id: int, user_id: int) -> Optional[DocumentSuggestion]:
        s_repo = SuggestionRepository(db)
        suggestion = s_repo.get_by_id(suggestion_id)
        if not suggestion or suggestion.status != "pending":
            return None

        doc_repo = DocumentRepository(db)
        doc = doc_repo.get_by_id(suggestion.document_id)
        if not _can_manage_shared_document_suggestion(db, doc, user_id, suggestion.suggestion_type, suggestion):
            return None

        s_repo.resolve(suggestion_id, status="kept", resolved_by=user_id)
        AuditService.log(
            db,
            action="SUGGESTION_KEEP_AS_IS",
            user_id=user_id,
            resource_type="document",
            resource_id=doc.uuid,
            detail={"type": suggestion.suggestion_type},
        )
        return suggestion

    def reject_suggestion(self, db: Session, suggestion_id: int, user_id: int) -> Optional[DocumentSuggestion]:
        s_repo = SuggestionRepository(db)
        suggestion = s_repo.get_by_id(suggestion_id)
        if not suggestion or suggestion.status != "pending":
            return None

        doc_repo = DocumentRepository(db)
        doc = doc_repo.get_by_id(suggestion.document_id)
        if not _can_manage_shared_document_suggestion(db, doc, user_id, suggestion.suggestion_type, suggestion):
            return None

        s_repo.resolve(suggestion_id, status="rejected", resolved_by=user_id)
        AuditService.log(db, action="SUGGESTION_REJECT", user_id=user_id, resource_type="document", resource_id=doc.uuid, detail={"type": suggestion.suggestion_type})
        return suggestion

    def bulk_accept_suggestions(self, db: Session, suggestion_ids: List[int], user_id: int, search_service=None) -> List[DocumentSuggestion]:
        accepted = []
        for sid in suggestion_ids:
            res = self.accept_suggestion(db, sid, user_id, search_service=search_service)
            if res:
                accepted.append(res)
        return accepted

    def bulk_reject_suggestions(self, db: Session, suggestion_ids: List[int], user_id: int) -> List[DocumentSuggestion]:
        rejected = []
        for sid in suggestion_ids:
            res = self.reject_suggestion(db, sid, user_id)
            if res:
                rejected.append(res)
        return rejected


    def analyze_library_suggestions(self, db: Session, user_id: int) -> List[DocumentSuggestion]:
        """
        Library-aware organization planning.

        Every owned, non-deleted document is analyzed with the existing
        per-document AI pipeline first. A second pass uses the resulting
        category/topic signals across the library to build coherent folder
        proposals. No document is modified until the user accepts a suggestion.

        MANUAL_BULK_ORG_V2
        """
        from collections import defaultdict
        from backend.models.document import DocumentModel

        s_repo = SuggestionRepository(db)

        user_docs = db.query(DocumentModel).filter(
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0
        ).all()

        generated: List[DocumentSuggestion] = []
        contexts = []

        # Pass 1: analyze every real document using the existing AI pipeline.
        for doc in user_docs:
            suggs = self.generate_suggestions_for_document(db, doc)
            if suggs:
                generated.extend(suggs)

            cat_s = s_repo.get_existing_for_document(doc.id, "categorize")
            tag_s = s_repo.get_existing_for_document(doc.id, "add_tag")

            category = (
                doc.category
                if doc.category and doc.category_source == "user_approved"
                else (cat_s.suggested_value if cat_s and cat_s.status == "pending" else doc.category)
            )
            category = (category or "General").strip()

            category_conf = 0.0
            if cat_s and cat_s.status == "pending" and cat_s.confidence is not None:
                category_conf = max(0.0, min(1.0, float(cat_s.confidence)))
            elif doc.category and doc.category_source == "user_approved":
                category_conf = 1.0

            tags = []
            if tag_s and tag_s.status == "pending":
                tags = [
                    part.strip().lower()
                    for part in str(tag_s.suggested_value or "").split(",")
                    if part.strip()
                ]

            contexts.append({
                "doc": doc,
                "category": category,
                "category_conf": category_conf,
                "tags": list(dict.fromkeys(tags)),
            })

        # Pass 2: build coherent topic clusters inside categories.
        generic_topic_tags = {
            "academic", "assignment", "document", "file", "general",
            "personal", "professional", "certificate", "project",
            "resume", "financial", "legal", "identity", "college"
        }

        by_category = defaultdict(list)
        for ctx in contexts:
            # Analyze already-organized documents, but only propose bulk moves
            # for currently unorganized documents.
            if ctx["doc"].folder_id:
                continue
            if not ctx["category"] or ctx["category"] == "General":
                continue
            by_category[ctx["category"]].append(ctx)

        used_doc_ids = set()

        for category, docs in sorted(by_category.items(), key=lambda item: item[0].lower()):
            tag_docs = defaultdict(list)
            for ctx in docs:
                for tag in ctx["tags"]:
                    if tag not in generic_topic_tags and len(tag) > 2:
                        tag_docs[tag].append(ctx)

            topic_candidates = [
                (tag, matches)
                for tag, matches in tag_docs.items()
                if len(matches) >= 2
            ]
            topic_candidates.sort(key=lambda item: (-len(item[1]), item[0]))

            category_conf_values = [
                ctx["category_conf"] for ctx in docs if ctx["category_conf"] > 0
            ]
            avg_category_conf = (
                sum(category_conf_values) / len(category_conf_values)
                if category_conf_values else 0.55
            )

            for topic, matches in topic_candidates:
                group = [ctx for ctx in matches if ctx["doc"].id not in used_doc_ids]
                if len(group) < 2:
                    continue

                coherence = min(1.0, len(group) / max(1, len(docs)))
                confidence = min(
                    0.96,
                    max(0.55, 0.70 * avg_category_conf + 0.30 * coherence)
                )

                clean_topic = re.sub(r"[^A-Za-z0-9 _-]+", "", topic).strip()
                clean_category = re.sub(r"[^A-Za-z0-9 _/-]+", "", category).strip()
                folder_name = f"{clean_category} - {clean_topic.title()}".strip(" -")
                if not folder_name:
                    continue

                doc_ids = sorted(ctx["doc"].id for ctx in group)
                reason = (
                    f"Suggested because {len(group)} unorganized documents in the "
                    f"'{category}' category share the topic '{topic}'. "
                    f"Library coherence is {coherence:.0%}; category evidence "
                    f"averages {avg_category_conf:.0%}. "
                    "The proposal is based on existing AI category/topic signals "
                    "and requires user approval before any move."
                )

                s = self.create_organization_group_suggestion(
                    db=db,
                    owner_id=user_id,
                    folder_name=folder_name,
                    doc_ids=doc_ids,
                    reason=reason,
                    confidence=confidence,
                    suggested_category=category,
                    suggested_tags=[topic],
                )

                if s:
                    generated.append(s)
                    used_doc_ids.update(doc_ids)

            # Remaining docs get a category-level fallback when there are at
            # least two of them; this is intentionally lower-confidence than
            # a shared-topic cluster.
            remaining = [
                ctx for ctx in docs
                if ctx["doc"].id not in used_doc_ids
            ]

            if len(remaining) >= 2:
                confidence = min(
                    0.90,
                    max(0.55, 0.85 * avg_category_conf + 0.10)
                )
                clean_category = re.sub(
                    r"[^A-Za-z0-9 _/-]+", "", category
                ).strip()
                folder_name = clean_category or "Organized Documents"

                doc_ids = sorted(ctx["doc"].id for ctx in remaining)
                reason = (
                    f"Suggested because {len(remaining)} unorganized documents "
                    f"share the '{category}' category. No stronger shared topic "
                    "cluster was found, so the category is used as the logical "
                    "folder boundary. Requires user approval."
                )

                s = self.create_organization_group_suggestion(
                    db=db,
                    owner_id=user_id,
                    folder_name=folder_name,
                    doc_ids=doc_ids,
                    reason=reason,
                    confidence=confidence,
                    suggested_category=category,
                )
                if s:
                    generated.append(s)

        return generated
# === IntelliDocs AI Organization V6 ===
# Append-only runtime overlay. No class-body rewriting is performed.
import json as _id_v6_json
import re as _id_v6_re

_ID_V6_STOP={
 "the","and","for","with","from","this","that","are","was","were","you",
 "register","login","logout","refresh","token","document","documents","upload",
 "updated","new","old","page","user","users","click","button","true","false",
 "screenshot","screen","image","png","jpg","jpeg","api","get","post","put","patch","delete",
 "http","https","www","com","null","none"
}

def _id_v6_clean(text):
    text=(text or "").strip()
    return "" if (not text or text.startswith("[Image document:")) else text

def _id_v6_tokens(text):
    vals=set()
    for tok in _id_v6_re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}",(text or "").lower()):
        if tok not in _ID_V6_STOP and len(tok)<=36 and not tok.isdigit(): vals.add(tok)
    return vals

def _id_v6_topics(doc):
    raw=getattr(doc,"key_topics",None)
    if isinstance(raw,str):
        try: raw=_id_v6_json.loads(raw)
        except Exception: raw=[]
    if not isinstance(raw,list): return []
    out=[]
    for x in raw:
        v=str(x or "").strip().lower()
        if v and v not in _ID_V6_STOP and not v.isdigit() and 1 < len(v) < 60 and v not in out: out.append(v)
    return out[:8]

def _id_v6_smart_name(doc):
    text=_id_v6_clean(getattr(doc,"extracted_text",""))
    if not text: return None
    low=text.lower(); original=(getattr(doc,"original_name","") or "").strip()
    ext=original.rsplit(".",1)[-1].lower() if "." in original else str(getattr(doc,"file_type","pdf") or "pdf").lower()
    if ext=="jpeg": ext="jpg"
    title=None
    if low.count("/auth/")+low.count("/documents/")>=3 and any(x in low for x in ("register","login","upload document","refresh token")):
        title="API Authentication and Document Endpoints"
    elif "swagger" in low or "openapi" in low: title="API Documentation"
    elif any(x in low for x in ("college fee","college fees","tuition fee","university fee","fee receipt","fee payment")): title="College Fee Payment Receipt"
    elif _id_v6_re.search(r"\b(fee|fees|tuition|payment|paid)\b",low) and _id_v6_re.search(r"\b(receipt|invoice|bill)\b",low): title="Fee Payment Receipt"
    elif _id_v6_re.search(r"\b(bank statement|account statement|ifsc|upi|transaction history)\b",low): title="Bank Account Statement"
    elif _id_v6_re.search(r"\b(invoice|invoices)\b",low): title="Invoice Document"
    elif _id_v6_re.search(r"\b(assignment|homework|problem set|submission)\b",low) and _id_v6_re.search(r"\b(dsa|data structures?|algorithms?)\b",low): title="DSA Assignment"
    elif _id_v6_re.search(r"\b(assignment|homework|problem set|submission)\b",low): title="Academic Assignment"
    elif _id_v6_re.search(r"\b(certificate|certification|completion|credential|diploma)\b",low): title="Certificate and Completion Document"
    elif _id_v6_re.search(r"\b(resume|curriculum vitae|professional profile|work experience)\b",low): title="Resume and Professional Profile"
    elif _id_v6_re.search(r"\b(aadhaar|pan card|passport|voter id|identity card|kyc)\b",low): title="Identity and KYC Document"
    elif _id_v6_re.search(r"\b(prescription|doctor|hospital|medicine|medical report|diagnosis)\b",low): title="Medical Document"
    else:
        topics=_id_v6_topics(doc)
        if len(topics)>=2: title=" ".join(x.title() for x in topics[:3])
        else:
            cat=str(getattr(doc,"category","") or "").strip(); toks=sorted(_id_v6_tokens(text))
            if cat and cat.lower()!="general" and toks: title=f"{cat.title()} {toks[0].title()}"
    if not title: return None
    title=_id_v6_re.sub(r"[^A-Za-z0-9 &_-]+","",title); title=_id_v6_re.sub(r"\s+"," ",title).strip()
    if len(title)<3: return None
    candidate=_id_v6_re.sub(r"\s+","_",title[:110].rstrip())+f".{ext or 'pdf'}"
    return None if candidate.lower()==original.lower() else candidate

def _id_v6_label(texts,fallback=None):
    blob=" ".join((x or "").lower() for x in texts)
    rules=[
      (r"(?:college|university).{0,60}(?:fee|fees|tuition|payment|receipt)|(?:fee|fees|tuition).{0,60}(?:college|university)","College Fees"),
      (r"bank|ifsc|upi|account statement|transaction","Bank Documents"),
      (r"assignment|homework|problem set|submission","Academic Assignments"),
      (r"certificate|certification|credential|diploma|completion","Certificates"),
      (r"resume|curriculum vitae|professional profile|work experience","Career Documents"),
      (r"aadhaar|pan card|passport|voter id|kyc|identity card","Identity Documents"),
      (r"prescription|doctor|hospital|medicine|medical report|diagnosis","Medical Documents"),
      (r"invoice|bill|gst|tax","Bills and Invoices"),
      (r"swagger|openapi|/auth/|/documents/","API Documentation"),
      (r"project|implementation|source code|readme|architecture","Project Documents")]
    for pat,label in rules:
        if _id_v6_re.search(pat,blob): return label
    return fallback

def _id_v6_path(fid,folders):
    names=[]; seen=set(); cur=folders.get(fid)
    while cur and cur.id not in seen:
        seen.add(cur.id); names.append(cur.name); cur=folders.get(cur.parent_id) if cur.parent_id else None
    return " / ".join(reversed(names))

def _id_v6_find_existing(db,user_id,docs,label,category):
    from backend.models.folder import FolderModel
    from backend.models.document import DocumentModel
    folders={f.id:f for f in db.query(FolderModel).filter(FolderModel.owner_id==user_id).all()}
    if not folders: return (None,None,0.0)
    ln=_id_v6_re.sub(r"[^a-z0-9]+"," ",(label or "").lower()).strip(); cn=(category or "").lower().strip()
    target=_id_v6_tokens(" ".join([label or "",category or ""]+[_id_v6_clean(getattr(d,"extracted_text","")) for d in docs]))
    best=(None,None,0.0)
    for fid in folders:
        path=_id_v6_path(fid,folders); leaf=path.split(" / ")[-1]
        leafnorm=_id_v6_re.sub(r"[^a-z0-9]+"," ",leaf.lower()).strip()
        exact=1.0 if ln and leafnorm==ln else 0.0
        catpath=1.0 if cn and cn in path.lower() else 0.0
        pt=_id_v6_tokens(path); lexical=len(target&pt)/max(1,len(target|pt))
        fdocs=db.query(DocumentModel).filter(DocumentModel.owner_id==user_id,DocumentModel.folder_id==fid,DocumentModel.is_deleted==0).limit(50).all()
        samecat=1.0 if category and any(str(getattr(x,"category","") or "").lower()==cn for x in fdocs) else 0.0
        score=0.62*exact+0.18*catpath+0.12*samecat+0.08*lexical
        if score>best[2]: best=(fid,path,score)
    return best if best[2]>=0.55 else (None,None,0.0)

def _id_v6_category_parent(db,user_id,category):
    from backend.models.folder import FolderModel
    c=str(category or "").strip().lower()
    if not c or c=="general": return None
    for f in db.query(FolderModel).filter(FolderModel.owner_id==user_id,FolderModel.parent_id==None).all():
        if str(f.name).strip().lower()==c: return f.id
    return None

def _id_v6_ev(s):
    try: return s.evidence if isinstance(s.evidence,dict) else _id_v6_json.loads(s.evidence or "{}")
    except Exception: return {}

_ID_V6_ORIGINAL_GENERATE = OrganizationService.generate_suggestions_for_document
_ID_V6_ORIGINAL_ANALYZE = OrganizationService.analyze_library_suggestions
_ID_V6_ORIGINAL_ACCEPT = OrganizationService.accept_suggestion

def _id_v6_generate(self,db,doc):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    suggestions=_ID_V6_ORIGINAL_GENERATE(self,db,doc) or []
    repo=SuggestionRepository(db)
    smart=_id_v6_smart_name(doc)
    old=repo.get_existing_for_document(doc.id,"rename")
    if old and old.status=="pending": repo.resolve(old.id,status="rejected",resolved_by=doc.owner_id)
    suggestions=[s for s in suggestions if not (s.suggestion_type=="rename" and s.status=="pending")]
    if smart:
        ev={"status_label":"PENDING","document_name":doc.original_name,"generated_filename":smart,"reason":"Contextual filename derived from document content/category; timestamp, UUID and generic screenshot noise are ignored."}
        suggestions.append(repo.create(document_id=doc.id,suggestion_type="rename",current_value=doc.original_name,suggested_value=smart,reason=ev["reason"],confidence=0.88,evidence=ev))
    db.commit(); return suggestions

def _id_v6_analyze(self,db,user_id):
    results=_ID_V6_ORIGINAL_ANALYZE(self,db,user_id) or []
    from backend.models.document import DocumentModel
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    repo=SuggestionRepository(db); suppressed=[]
    for s in list(results):
        if s.suggestion_type!="create_folder_group" or s.status!="pending": continue
        ev=_id_v6_ev(s); ids=[int(x) for x in (ev.get("document_ids") or []) if str(x).isdigit()]
        if len(ids)<2: continue
        docs=db.query(DocumentModel).filter(DocumentModel.owner_id==user_id,DocumentModel.id.in_(ids),DocumentModel.is_deleted==0).all()
        if len(docs)<2: continue
        category=str(ev.get("category") or next((getattr(d,"category","") for d in docs if getattr(d,"category",None)),"General") or "General")
        label=ev.get("suggested_folder_name") or s.suggested_value or _id_v6_label([getattr(d,"extracted_text","") for d in docs]) or category
        fid,path,fs=_id_v6_find_existing(db,user_id,docs,label,category)
        parent=None if fid else _id_v6_category_parent(db,user_id,category)
        target=path if fid else (f"{category} / {label}" if parent else label)
        ev.update({"target_mode":"existing" if fid else "new","target_folder_id":fid,"target_parent_id":parent,"target_folder_path":target,"suggested_folder_name":label,"category":category,"document_ids":ids,"document_names":[d.original_name for d in docs],"status_label":"PENDING","reason":(f"These {len(docs)} documents share strong contextual signals around {label}. An existing folder '{path}' matches the group." if fid else f"These {len(docs)} documents share strong contextual signals around {label}. No suitable existing folder matched, so a new folder is proposed under '{category}' when available.")})
        s.suggested_value=target; s.reason=ev["reason"]; s.confidence=min(0.98,max(float(s.confidence or 0),float(fs or 0))); s.evidence=_id_v6_json.dumps(ev)
        sig=(tuple(sorted(ids)),str(ev.get("target_mode")),int(fid or 0),target.lower())
        for prior in db.query(type(s)).filter(type(s).suggestion_type=="create_folder_group",type(s).id!=s.id).all():
            pev=_id_v6_ev(prior); ps=(tuple(sorted(int(x) for x in (pev.get("document_ids") or []) if str(x).isdigit())),str(pev.get("target_mode")),int(pev.get("target_folder_id") or 0),str(pev.get("target_folder_path") or "").lower())
            if ps==sig and prior.status in {"kept","rejected"}:
                repo.resolve(s.id,status=prior.status,resolved_by=user_id); suppressed.append(s.id); break
    db.commit(); return [x for x in results if x.id not in set(suppressed)]

def _id_v6_accept(self,db,suggestion_id,user_id,search_service=None):
    from backend.database.repositories.document_repo import DocumentRepository
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel
    repo=SuggestionRepository(db); s=repo.get_by_id(suggestion_id)
    if not s or s.status!="pending": return None
    doc=DocumentRepository(db).get_by_id(s.document_id)
    if not doc or doc.owner_id!=user_id: return None
    if s.suggestion_type!="create_folder_group": return _ID_V6_ORIGINAL_ACCEPT(self,db,suggestion_id,user_id,search_service)
    ev=_id_v6_ev(s); ids=[int(x) for x in (ev.get("document_ids") or [doc.id]) if str(x).isdigit()]; mode=ev.get("target_mode","new")
    if mode=="existing":
        folder=db.query(FolderModel).filter(FolderModel.id==int(ev.get("target_folder_id") or 0),FolderModel.owner_id==user_id).first()
        if not folder: return None
    else:
        name=str(ev.get("suggested_folder_name") or s.suggested_value or "").strip(); parent=ev.get("target_parent_id")
        if not name: return None
        folder=db.query(FolderModel).filter(FolderModel.owner_id==user_id,FolderModel.parent_id==parent,FolderModel.name==name).first()
        if not folder: folder=FolderModel(name=name,owner_id=user_id,parent_id=parent); db.add(folder); db.flush()
    moved=0
    for did in ids:
        d=db.query(DocumentModel).filter(DocumentModel.id==did,DocumentModel.owner_id==user_id,DocumentModel.is_deleted==0).first()
        if d: d.folder_id=folder.id; moved+=1
    if not moved: return None
    repo.resolve(suggestion_id,status="accepted",resolved_by=user_id); db.commit(); db.refresh(s); return s

OrganizationService.generate_suggestions_for_document=_id_v6_generate
OrganizationService.analyze_library_suggestions=_id_v6_analyze
OrganizationService.accept_suggestion=_id_v6_accept

# === IntelliDocs AI Organization V8 ===
# Append-only runtime overlay. Builds contextual groups, reuses existing folders,
# creates category/child folder paths only when needed, and supports automatic
# post-upload analysis without changing the security/quarantine pipeline.
import json as _id_v7_json
import re as _id_v7_re
from collections import defaultdict as _id_v7_defaultdict

_ID_V7_STOP = {
    "the","and","for","with","from","this","that","are","was","were",
    "you","your","our","their","document","documents","file","page",
    "image","screenshot","screen","uploaded","created","new","old",
    "api","get","post","put","patch","delete","http","https","www",
    "com","register","login","logout","refresh","token","button","click",
    "true","false","none","null","general","system","user","users",
    "college","university","academic","financial","assignment","certificate",
    "personal","professional","project","identity","legal","resume","cv"
}


def _id_v7_norm(value):
    return _id_v7_re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _id_v7_tokens(text):
    vals = []
    seen = set()
    for tok in _id_v7_re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", (text or "").lower()):
        if tok in _ID_V7_STOP or tok.isdigit() or len(tok) > 36:
            continue
        if tok not in seen:
            seen.add(tok)
            vals.append(tok)
    return vals


def _id_v7_text(doc):
    text = str(getattr(doc, "extracted_text", "") or "").strip()
    if text.startswith("[Image document:"):
        text = ""
    name = str(getattr(doc, "original_name", "") or "")
    return f"{name} {text[:10000]}".strip()


def _id_v7_context(doc):
    blob = _id_v7_text(doc).lower()
    name = str(getattr(doc, "original_name", "") or "")
    category = str(getattr(doc, "category", "") or "").strip()

    # Strong artifact/context rules. These intentionally outrank weak single words.
    fee = bool(_id_v7_re.search(r"\b(fee|fees|tuition)\b", blob))
    finance_artifact = bool(_id_v7_re.search(r"\b(receipt|payment|paid|invoice|bill|amount due|transaction|bank statement|account statement|gst|tax)\b", blob))
    college_context = bool(_id_v7_re.search(r"\b(college|university|student|semester|campus|admission|exam)\b", blob))

    if fee and (college_context or finance_artifact):
        ctx_cat = "Financial"
        label = "College Fees" if college_context else "Fees"
        strong = True
        signals = [x for x in ("fee/fees", "college/university" if college_context else None, "receipt/payment" if finance_artifact else None) if x]
    elif _id_v7_re.search(r"\b(bank statement|account statement|ifsc|upi|transaction history)\b", blob):
        ctx_cat, label, strong = "Financial", "Bank Statements", True
        signals = ["bank/statement/transaction"]
    elif _id_v7_re.search(r"\b(invoice|bill|gst|tax|amount due)\b", blob):
        ctx_cat, label, strong = "Financial", "Bills & Invoices", True
        signals = ["invoice/bill/tax"]
    elif _id_v7_re.search(r"\b(dsa|data structures?|algorithms?)\b", blob) and _id_v7_re.search(r"\b(assignment|homework|submission|problem set|lab report)\b", blob):
        ctx_cat, label, strong = "Assignment", "DSA Assignments", True
        signals = ["DSA/data structures/algorithms", "assignment"]
    elif _id_v7_re.search(r"\b(assignment|homework|submission|problem set|lab report)\b", blob):
        ctx_cat, label, strong = "Assignment", "Academic Assignments", True
        signals = ["assignment/homework/submission"]
    elif _id_v7_re.search(r"\b(certificate|certification|credential|diploma|completion|awarded)\b", blob):
        ctx_cat, label, strong = "Certificate", "Certificates", True
        signals = ["certificate/certification/completion"]
    elif _id_v7_re.search(r"\b(resume|curriculum vitae|professional profile|work experience)\b", blob):
        ctx_cat, label, strong = "Resume/CV", "Career Documents", True
        signals = ["resume/cv/career"]
    elif _id_v7_re.search(r"\b(aadhaar|pan card|passport|voter id|kyc|identity card)\b", blob):
        ctx_cat, label, strong = "Identity", "Identity Documents", True
        signals = ["identity/kyc"]
    elif _id_v7_re.search(r"\b(agreement|contract|nda|deed|power of attorney|terms and conditions)\b", blob):
        ctx_cat, label, strong = "Legal", "Legal Documents", True
        signals = ["agreement/contract/legal"]
    else:
        ctx_cat = category if category and category.lower() != "general" else "General"
        # Prefer meaningful stored topics when available.
        topics = getattr(doc, "key_topics", None)
        if isinstance(topics, str):
            try:
                topics = _id_v7_json.loads(topics)
            except Exception:
                topics = []
        topics = [str(x).strip().lower() for x in (topics or []) if str(x).strip()]
        meaningful = [x for x in topics if x not in _ID_V7_STOP and not x.isdigit()]
        if len(meaningful) >= 1 and ctx_cat != "General":
            label = " ".join(part.title() for part in meaningful[:2])
            strong = len(meaningful) >= 2
            signals = meaningful[:3]
        else:
            terms = [x for x in _id_v7_tokens(blob) if len(x) >= 4]
            label = " ".join(x.title() for x in terms[:2]) if len(terms) >= 2 else None
            strong = False
            signals = terms[:3]

    return {
        "category": ctx_cat or "General",
        "label": label,
        "strong": bool(strong),
        "signals": signals,
        "tokens": set(_id_v7_tokens(blob)),
        "text": blob,
        "name": name,
    }


def _id_v7_path(fid, folders):
    names = []
    seen = set()
    cur = folders.get(fid)
    while cur and cur.id not in seen:
        seen.add(cur.id)
        names.append(str(cur.name))
        cur = folders.get(cur.parent_id) if cur.parent_id else None
    return " / ".join(reversed(names))


def _id_v7_existing_folders(db, owner_id):
    from backend.models.folder import FolderModel
    return {f.id: f for f in db.query(FolderModel).filter(FolderModel.owner_id == owner_id).all()}


def _id_v7_find_category_root(folders, category):
    c = _id_v7_norm(category)
    if not c or c == "general":
        return None
    for f in folders.values():
        if f.parent_id is None and _id_v7_norm(f.name) == c:
            return f
    return None


def _id_v7_match_existing(db, user_id, folders, contexts, category, label):
    if not folders or not label:
        return (None, None, 0.0)
    target = set(_id_v7_tokens(f"{label} {category}"))
    cn = _id_v7_norm(category)
    ln = _id_v7_norm(label)
    best = (None, None, 0.0)
    from backend.models.document import DocumentModel

    for fid, folder in folders.items():
        path = _id_v7_path(fid, folders)
        leaf_norm = _id_v7_norm(folder.name)
        if not leaf_norm:
            continue
        leaf_tokens = set(_id_v7_tokens(folder.name))
        overlap = len(target & leaf_tokens) / max(1, len(target | leaf_tokens))
        exact = 1.0 if leaf_norm == ln else 0.0
        category_path = 0.45 if cn and cn in _id_v7_norm(path).split() else 0.0
        if cn and cn in _id_v7_norm(path):
            category_path = 0.40
        fdocs = db.query(DocumentModel).filter(
            DocumentModel.owner_id == user_id,
            DocumentModel.folder_id == fid,
            DocumentModel.is_deleted == 0
        ).limit(80).all()
        samecat = 1.0 if any(_id_v7_norm(getattr(d, "category", "")) == cn for d in fdocs) else 0.0
        # 'Fees' should match 'College Fees' when the folder sits in a Financial path
        # or contains Financial docs; exact label remains strongest.
        score = 0.62 * exact + 0.24 * overlap + 0.10 * samecat + 0.04 * category_path
        if score > best[2]:
            best = (fid, path, score)
    # A leaf such as "Fees" is a valid match for the contextual label
    # "College Fees" even without exact string equality.
    return best if best[2] >= 0.38 else (None, None, 0.0)


def _id_v7_group_key(doc_ids, target_path, category, label):
    return "|".join([
        ",".join(str(x) for x in sorted(set(doc_ids))),
        _id_v7_norm(target_path),
        _id_v7_norm(category),
        _id_v7_norm(label),
    ])


def _id_v7_evidence(suggestion):
    try:
        return suggestion.evidence if isinstance(suggestion.evidence, dict) else _id_v7_json.loads(suggestion.evidence or "{}")
    except Exception:
        return {}


def _id_v7_existing_resolution(db, user_id, group_key):
    from backend.models.document import DocumentModel
    from backend.models.suggestion import DocumentSuggestion
    candidates = db.query(DocumentSuggestion).join(
        DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
    ).filter(
        DocumentSuggestion.suggestion_type == "create_folder_group",
        DocumentModel.owner_id == user_id
    ).all()
    for s in candidates:
        ev = _id_v7_evidence(s)
        if ev.get("v7_group_key") == group_key and s.status in {"accepted", "rejected", "kept"}:
            return s.status
    return None


def _id_v7_upsert_group(db, user_id, docs, category, label, signals, strong, semantic_score=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.suggestion import DocumentSuggestion
    from backend.models.document import DocumentModel

    if len(docs) < 2:
        return None
    folders = _id_v7_existing_folders(db, user_id)
    target_id, target_path, folder_score = _id_v7_match_existing(db, user_id, folders, docs, category, label)
    category_root = _id_v7_find_category_root(folders, category)
    target_mode = "existing" if target_id else "new"
    target_parent_id = category_root.id if (not target_id and category_root) else None
    if target_id:
        destination = target_path
    elif category_root:
        destination = f"{category_root.name} / {label}"
    else:
        destination = f"{category} / {label}"

    doc_ids = sorted(int(d.id) for d in docs)
    group_key = _id_v7_group_key(doc_ids, destination, category, label)
    resolved = _id_v7_existing_resolution(db, user_id, group_key)
    if resolved:
        return None

    confidence = 0.88 if strong else 0.76
    if semantic_score is not None:
        confidence += max(0.0, min(0.06, (float(semantic_score) - 0.55) * 0.2))
    if target_id:
        confidence += 0.04
    confidence = min(0.97, round(confidence, 2))

    reason_bits = [
        f"{len(docs)} documents share the contextual theme '{label}'",
        f"category '{category}'",
    ]
    if signals:
        reason_bits.append("signals: " + ", ".join(str(x) for x in signals[:5]))
    if semantic_score is not None:
        reason_bits.append(f"semantic similarity {float(semantic_score):.0%}")
    if target_id:
        reason_bits.append(f"existing folder match '{target_path}'")
    else:
        reason_bits.append("no suitable existing folder matched")

    reason = ". ".join(reason_bits) + ". User approval is required before any document is moved or any folder is created."
    evidence = {
        "v7_group_key": group_key,
        "document_ids": doc_ids,
        "document_names": [d.original_name for d in docs],
        "category": category,
        "suggested_category": category,
        "suggested_folder_name": label,
        "target_mode": target_mode,
        "target_folder_id": target_id,
        "target_parent_id": target_parent_id,
        "target_folder_path": destination,
        "shared_signals": list(signals or [])[:8],
        "semantic_similarity": round(float(semantic_score), 3) if semantic_score is not None else None,
        "status_label": "PENDING",
        "strong_context": bool(strong),
    }

    repo = SuggestionRepository(db)
    existing = None
    # Update a matching pending proposal if it already exists.
    for s in db.query(DocumentSuggestion).filter(DocumentSuggestion.suggestion_type == "create_folder_group", DocumentSuggestion.status == "pending").all():
        ev = _id_v7_evidence(s)
        if ev.get("v7_group_key") == group_key:
            existing = s
            break

    if existing:
        existing.suggested_value = destination
        existing.reason = reason
        existing.confidence = confidence
        existing.evidence = _id_v7_json.dumps(evidence)
        db.commit()
        db.refresh(existing)
        return existing

    primary = docs[0]
    s = repo.create(
        document_id=primary.id,
        suggestion_type="create_folder_group",
        current_value="Unorganized",
        suggested_value=destination,
        reason=reason,
        confidence=confidence,
        evidence=evidence,
    )
    try:
        from backend.core.notification_service import NotificationService
        NotificationService.notify(
            db,
            user_id=user_id,
            event_type="AI_ORGANIZATION_SUGGESTION_READY",
            title="Smart Organization Suggestion Ready",
            message=f"{len(docs)} documents can be organized under '{destination}'.",
            document_id=primary.id,
        )
    except Exception:
        pass
    return s


def _id_v7_semantic_score(self, contexts):
    # Optional local embedding signal. Failure is safe and simply returns None.
    if not getattr(self, "embedding_engine", None):
        return None
    try:
        engine = self.embedding_engine
        if not engine.is_available() or len(contexts) < 2:
            return None
        vectors = [engine.encode(c["text"][:4000]) for c in contexts[:8]]
        if not vectors or any(v is None for v in vectors):
            return None
        scores = []
        base = vectors[0]
        for other in vectors[1:]:
            score = float((base * other).sum())
            scores.append(score)
        return max(scores) if scores else None
    except Exception:
        return None


def _id_v7_analyze(self, db, user_id):
    from backend.models.document import DocumentModel
    from backend.database.repositories.suggestion_repo import SuggestionRepository

    docs = db.query(DocumentModel).filter(
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).all()

    contexts = [(doc, _id_v7_context(doc)) for doc in docs]
    generated = []
    unorganized = [(doc, ctx) for doc, ctx in contexts if not getattr(doc, "folder_id", None)]
    organized = [(doc, ctx) for doc, ctx in contexts if getattr(doc, "folder_id", None)]

    # Explicit contextual groups: two or more unorganized docs with the same
    # meaningful destination label/category.
    clusters = _id_v7_defaultdict(list)
    for doc, ctx in unorganized:
        label = ctx.get("label")
        category = ctx.get("category") or "General"
        if not label or category.lower() == "general":
            continue
        clusters[(_id_v7_norm(category), _id_v7_norm(label))].append((doc, ctx))

    used = set()
    for (_cat_norm, _label_norm), members in clusters.items():
        if len(members) < 2:
            continue
        category = members[0][1]["category"]
        label = members[0][1]["label"]
        # Same label/category is already a high-context relationship. Optional
        # semantic score merely strengthens the confidence explanation.
        sem = _id_v7_semantic_score(self, [m[1] for m in members])
        signals = sorted({sig for _, c in members for sig in c.get("signals", [])})[:6]
        strong = all(bool(c.get("strong")) for _, c in members)
        suggestion = _id_v7_upsert_group(
            db, user_id, [m[0] for m in members], category, label, signals, strong, sem
        )
        if suggestion:
            generated.append(suggestion)
            used.update(m[0].id for m in members)

    # New-document routing into an existing folder is intentionally handled
    # through the same >=2 document grouping proposal so this page remains a
    # true grouping workflow rather than becoming a noisy auto-classifier.

    # Fallback: category-level groups only when at least two docs share the same
    # non-generic category and have at least one overlapping meaningful signal.
    by_cat = _id_v7_defaultdict(list)
    for doc, ctx in unorganized:
        cat = ctx.get("category") or "General"
        if cat.lower() == "general" or doc.id in used:
            continue
        by_cat[_id_v7_norm(cat)].append((doc, ctx))

    for _cat_norm, members in by_cat.items():
        if len(members) < 2:
            continue
        shared = set.intersection(*(c.get("tokens", set()) for _, c in members)) if members else set()
        shared = {x for x in shared if len(x) >= 4 and x not in _ID_V7_STOP}
        if not shared:
            continue
        category = members[0][1]["category"]
        label = " & ".join(x.title() for x in sorted(shared)[:2])
        suggestion = _id_v7_upsert_group(
            db, user_id, [m[0] for m in members], category, label, sorted(shared)[:5], False, None
        )
        if suggestion:
            generated.append(suggestion)

    db.commit()
    return generated


def _id_v7_accept(self, db, suggestion_id, user_id, search_service=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.database.repositories.document_repo import DocumentRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel
    from backend.models.category import CategoryModel

    repo = SuggestionRepository(db)
    s = repo.get_by_id(suggestion_id)
    if not s or s.status != "pending":
        return None
    primary = DocumentRepository(db).get_by_id(s.document_id)
    if not primary or primary.owner_id != user_id:
        return None
    if s.suggestion_type != "create_folder_group":
        return _ID_V7_ORIGINAL_ACCEPT(self, db, suggestion_id, user_id, search_service)

    ev = _id_v7_evidence(s)
    doc_ids = [int(x) for x in (ev.get("document_ids") or [primary.id]) if str(x).isdigit()]
    category = str(ev.get("suggested_category") or ev.get("category") or "General").strip()
    label = str(ev.get("suggested_folder_name") or "").strip()
    mode = str(ev.get("target_mode") or "new")
    target_id = ev.get("target_folder_id")
    parent_id = ev.get("target_parent_id")

    folder = None
    if mode == "existing" and target_id:
        folder = db.query(FolderModel).filter(
            FolderModel.id == int(target_id), FolderModel.owner_id == user_id
        ).first()
        if not folder:
            return None
    else:
        # Reuse existing category root or create it only because the user approved
        # the organization suggestion; never create folders during analysis.
        if parent_id:
            parent = db.query(FolderModel).filter(
                FolderModel.id == int(parent_id), FolderModel.owner_id == user_id
            ).first()
        else:
            parent = None
            if category.lower() != "general":
                parent = db.query(FolderModel).filter(
                    FolderModel.owner_id == user_id,
                    FolderModel.parent_id == None,
                    FolderModel.name == category,
                ).first()
                if not parent:
                    parent = FolderModel(name=category, owner_id=user_id, parent_id=None)
                    db.add(parent)
                    db.flush()
        folder = db.query(FolderModel).filter(
            FolderModel.owner_id == user_id,
            FolderModel.parent_id == (parent.id if parent else None),
            FolderModel.name == label,
        ).first()
        if not folder:
            folder = FolderModel(
                name=label or category or "Organized Documents",
                owner_id=user_id,
                parent_id=parent.id if parent else None,
            )
            db.add(folder)
            db.flush()

    cat_obj = None
    if category and category.lower() != "general":
        cat_obj = db.query(CategoryModel).filter(
            CategoryModel.name == category,
            ((CategoryModel.is_system == 1) | (CategoryModel.owner_id == user_id))
        ).first()

    moved = []
    for did in doc_ids:
        d = db.query(DocumentModel).filter(
            DocumentModel.id == did,
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0,
        ).first()
        if not d:
            continue
        d.folder_id = folder.id
        if category and category.lower() != "general":
            d.category = category
            d.category_source = "user_approved"
            if cat_obj:
                d.category_id = cat_obj.id
        moved.append(d)

    if not moved:
        return None

    repo.resolve(suggestion_id, status="accepted", resolved_by=user_id)
    try:
        from backend.core.audit_service import AuditService
        AuditService.log(
            db,
            action="SUGGESTION_ACCEPT_ORGANIZATION",
            user_id=user_id,
            resource_type="folder",
            resource_id=str(folder.id),
            detail={
                "folder_name": folder.name,
                "parent_id": folder.parent_id,
                "category": category,
                "document_count": len(moved),
                "document_ids": [d.id for d in moved],
            },
        )
    except Exception:
        pass
    db.commit()
    db.refresh(s)
    return s


_ID_V7_ORIGINAL_ACCEPT = OrganizationService.accept_suggestion
OrganizationService.analyze_library_suggestions = _id_v7_analyze
OrganizationService.accept_suggestion = _id_v7_accept
# === IntelliDocs AI Organization V9 Audit Hardening ===
# Guard rails layered on top of the existing organization service. This patch
# intentionally preserves the existing service/API architecture and approval flow.
import json as _id_v9_json
import logging as _id_v9_logging
import re as _id_v9_re

_ID_V9_LOG = _id_v9_logging.getLogger(__name__)
_ID_V9_ORIGINAL_SAVE = OrganizationService._save_or_update_suggestion
_ID_V9_ORIGINAL_TAGS = OrganizationService._infer_contextual_tags
_ID_V9_ORIGINAL_GENERATE = _ID_V6_ORIGINAL_GENERATE
_ID_V9_GROUP_ANALYZE = OrganizationService.analyze_library_suggestions
_ID_V9_GROUP_UPSERT = _id_v7_upsert_group
_ID_V9_GROUP_MATCH = _id_v7_match_existing
_ID_V9_ORIGINAL_ACCEPT = OrganizationService.accept_suggestion

_ID_V9_SAVE_TAG_STOP = {
    "main", "home", "user", "users", "personal", "page", "screen", "screenshot",
    "image", "scan", "scanned", "copy", "final", "latest", "new", "old",
    "document", "documents", "file", "files", "pdf", "docx", "png", "jpg",
    "jpeg", "general", "unknown", "none", "null", "true", "false", "cv", "resumecv", "resume_cv", "curriculum",
    "upload", "uploaded", "download", "export", "backup", "temp", "tmp",
}
_ID_V9_TAG_RULES = (
    (r"\b(college|university|campus|admission)\b", "college"),
    (r"\b(fees?|tuition)\b", "fees"),
    (r"\b(receipt|payment receipt)\b", "receipt"),
    (r"\b(semester|academic year|term)\b", "semester"),
    (r"\b(bank statement|account statement|ifsc|upi|transaction history)\b", "bank statement"),
    (r"\b(invoice|gst|tax|amount due)\b", "invoice"),
    (r"\b(data structures?|algorithms?|\bdsa\b)\b", "dsa"),
    (r"\b(assignment|homework|problem set|lab report|submission)\b", "assignment"),
    (r"\b(certificate|certification|credential|diploma|completion)\b", "certificate"),
    (r"\b(resume|curriculum vitae|\bcv\b|work experience)\b", "resume"),
    (r"\bpython\b", "python"),
    (r"\bjavascript\b", "javascript"),
    (r"\btypescript\b", "typescript"),
    (r"\bhtml\b", "html"),
    (r"\bcss\b", "css"),
    (r"\breact\b", "react"),
    (r"\bfastapi\b", "fastapi"),
    (r"\bflask\b", "flask"),
    (r"\b(aadhaar|pan card|passport|voter id|kyc|identity card)\b", "identity"),
    (r"\b(agreement|contract|nda|deed|terms and conditions)\b", "legal"),
)


def _id_v9_json_value(value):
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = _id_v9_json.loads(value) if isinstance(value, str) else value
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _id_v9_same_sensitivity(left, right):
    try:
        a = OrganizationService.normalize_sensitivity(str(left or "public"))
        b = OrganizationService.normalize_sensitivity(str(right or "public"))
        return bool(a and b and a == b)
    except Exception:
        return str(left or "public").strip().lower() == str(right or "public").strip().lower()


def _id_v9_save_or_update(self, db, s_repo, doc, suggestion_type, current_val,
                          suggested_val, reason, confidence, evidence):
    existing = s_repo.get_existing_for_document(doc.id, suggestion_type)

    # Do not offer a sensitivity change whose normalized value is already active.
    if suggestion_type == "sensitivity" and _id_v9_same_sensitivity(current_val, suggested_val):
        if existing and existing.status == "pending":
            s_repo.resolve(existing.id, status="kept", resolved_by=doc.owner_id)
        return None

    # Re-evaluation should not rewrite unchanged pending rows or trigger another
    # notification for exactly the same recommendation.
    if existing and existing.status == "pending":
        old_evidence = _id_v9_json_value(existing.evidence)
        new_evidence = evidence if isinstance(evidence, dict) else _id_v9_json_value(evidence)
        same = (
            (existing.current_value or "") == (current_val or "")
            and (existing.suggested_value or "") == (suggested_val or "")
            and (existing.reason or "") == (reason or "")
            and abs(float(existing.confidence or 0) - float(confidence or 0)) < 0.000001
            and old_evidence == (new_evidence or {})
        )
        if same:
            return None

    return _ID_V9_ORIGINAL_SAVE(self, db, s_repo, doc, suggestion_type,
                                current_val, suggested_val, reason, confidence, evidence)


def _id_v9_tags(self, filename, text_lower, category, pii_types=None):
    """Build a stable, deduplicated, relevance-first tag list (no set-order leakage)."""
    text = str(text_lower or "").lower()
    filename_no_ext = _id_v9_re.sub(r"\.[^/.]+$", "", str(filename or "")).lower()
    tags = []
    seen = set()

    def add(value):
        value = _id_v9_re.sub(r"\s+", " ", str(value or "").strip().lower())
        if not value or value in _ID_V9_SAVE_TAG_STOP or len(value) < 2 or len(value) > 36:
            return
        if value.isdigit() or _id_v9_re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", value):
            return
        if _id_v9_re.fullmatch(r"[+()\d\s.-]{7,}", value):
            return
        if value not in seen:
            seen.add(value)
            tags.append(value)

    # Signals visible in the extracted text get priority over arbitrary filename words.
    for pattern, tag in _ID_V9_TAG_RULES:
        if _id_v9_re.search(pattern, text):
            add(tag)

    # Keep useful filename terms in original order, while dropping duplicate/noise tokens.
    expansions = globals().get("FILENAME_EXPANSIONS", {})
    for token in _id_v9_re.split(r"[_\s.-]+", filename_no_ext):
        token = token.strip().lower()
        if not token:
            continue
        expanded = expansions.get(token)
        if expanded:
            for piece in _id_v9_re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{1,35}", str(expanded)):
                add(piece)
        else:
            add(token)

    cat = str(category or "").strip().lower().replace("/", "_")
    if cat not in {"", "general", "uncategorized", "personal", "academic", "assignment", "financial", "professional", "project", "identity", "legal", "certificate", "resume_cv"}:
        add(cat)

    return tags[:5]


def _id_v9_smart_name(doc):
    """Reuse contextual rules, but normalize duplicate/noisy terms in the filename."""
    original = str(getattr(doc, "original_name", "") or "document.pdf").strip()
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else str(getattr(doc, "file_type", "pdf") or "pdf").lower()
    if ext == "jpeg":
        ext = "jpg"
    ext = _id_v9_re.sub(r"[^a-z0-9]+", "", ext) or "pdf"
    text = str(getattr(doc, "extracted_text", "") or "")
    combined = f"{original} {text}"
    low = combined.lower()

    # A CV with multiple web technologies is a Resume/Web Development document,
    # not a repeated token list such as Resume_CV_HTML_CSS_Web_HTML.
    if _id_v9_re.search(r"\b(resume|curriculum vitae|\bcv\b)\b", low):
        candidate = (f"Resume_Web_Development.{ext}" if _id_v9_re.search(
            r"\b(html|css|javascript|typescript|web development|react|frontend|front end)\b", low
        ) else f"Resume.{ext}")
        current = str(getattr(doc, "display_name", None) or original).strip()
        return None if candidate.casefold() == original.casefold() or candidate.casefold() == current.casefold() else candidate

    base = _id_v6_smart_name(doc)
    if not base:
        return None
    title = base.rsplit(".", 1)[0]
    raw_words = _id_v9_re.findall(r"[A-Za-z][A-Za-z0-9-]{1,35}", title)
    cleaned = []
    seen = set()
    noise = _ID_V9_SAVE_TAG_STOP | {"cv", "copy", "final", "document", "profile"}
    for word in raw_words:
        low_word = word.lower()
        if low_word in noise or low_word in seen:
            continue
        seen.add(low_word)
        cleaned.append(word.capitalize())
    if not cleaned:
        return None
    candidate = "_".join(cleaned[:7]) + f".{ext}"
    current = str(getattr(doc, "display_name", None) or original).strip()
    return None if candidate.casefold() == original.casefold() or candidate.casefold() == current.casefold() else candidate


def _id_v9_generate(self, db, doc):
    from backend.database.repositories.suggestion_repo import SuggestionRepository

    # Bypass the old V6 wrapper: it rejected/recreated a pending rename on every scan.
    suggestions = _ID_V9_ORIGINAL_GENERATE(self, db, doc) or []
    repo = SuggestionRepository(db)
    smart = _id_v9_smart_name(doc)
    if not smart:
        return suggestions

    old = repo.get_existing_for_document(doc.id, "rename")
    evidence = {
        "status_label": "PENDING",
        "document_name": doc.original_name,
        "generated_filename": smart,
        "reason": "Contextual filename derived from document content/category; repeated terms and generic file noise are removed.",
    }
    changed = False
    target = None
    if old and old.status == "pending":
        changed = (
            (old.suggested_value or "") != smart
            or (old.current_value or "") != (getattr(doc, "display_name", None) or doc.original_name)
            or _id_v9_json_value(old.evidence) != evidence
        )
        old.current_value = getattr(doc, "display_name", None) or doc.original_name
        old.suggested_value = smart
        old.reason = evidence["reason"]
        old.confidence = 0.88
        old.evidence = _id_v9_json.dumps(evidence)
        db.add(old)
        db.commit()
        db.refresh(old)
        target = old
    elif old and old.status in {"accepted", "rejected", "kept"} and old.suggested_value == smart:
        target = None
    else:
        target = repo.create(
            document_id=doc.id,
            suggestion_type="rename",
            current_value=getattr(doc, "display_name", None) or doc.original_name,
            suggested_value=smart,
            reason=evidence["reason"],
            confidence=0.88,
            evidence=evidence,
        )
        changed = True

    # Preserve one pending rename card; all other suggestion types retain their existing behavior.
    non_rename = [s for s in suggestions if not (s.suggestion_type == "rename" and s.status == "pending")]
    if target is not None and target.status == "pending":
        non_rename.append(target)
    unique = []
    seen_ids = set()
    for suggestion in non_rename:
        sid = getattr(suggestion, "id", None)
        if sid is None or sid not in seen_ids:
            unique.append(suggestion)
            if sid is not None:
                seen_ids.add(sid)

    # The original generator already emits one notification when it generated
    # a new/changed proposal. Emit one here only if the smart name was the sole change.
    if changed and not suggestions:
        try:
            from backend.core.notification_service import NotificationService
            NotificationService.notify(
                db,
                user_id=doc.owner_id,
                event_type="SUGGESTION_READY",
                title="Organization Suggestions Available",
                message=f"IntelliDocs updated a smart filename suggestion for '{doc.original_name}'.",
                document_id=doc.id,
            )
        except Exception:
            _ID_V9_LOG.exception("Could not create smart-name notification for document %s", doc.id)
    return unique


# Group proposals should be explainable artifact-level clusters, not arbitrary
# names/topics that happen to overlap. Weak category-only fallback groups are withheld.
_ID_V9_ALLOWED_GROUP_LABELS = {
    "college fees", "fees", "bank statements", "bills invoices",
    "dsa assignments", "academic assignments", "certificates", "career documents",
    "identity documents", "legal documents",
}


def _id_v9_upsert_group(db, user_id, docs, category, label, signals, strong, semantic_score=None):
    normalized = _id_v7_norm(label)
    if len(docs or []) < 2 or not strong or normalized not in _ID_V9_ALLOWED_GROUP_LABELS:
        return None
    return _ID_V9_GROUP_UPSERT(db, user_id, docs, category, label, signals, True, semantic_score)


def _id_v9_match_existing(db, user_id, folders, contexts, category, label):
    match = _ID_V9_GROUP_MATCH(db, user_id, folders, contexts, category, label)
    folder_id, path, score = match
    if not folder_id or not path:
        return (None, None, 0.0)
    if score >= 0.60:
        return match
    # Explicit safe alias: a folder named Fees can serve College Fees only under
    # a Financial path; otherwise a low lexical match must not silently redirect docs.
    leaf = _id_v7_norm(path.split(" / ")[-1])
    cat = _id_v7_norm(category)
    if cat == "financial" and _id_v7_norm(label) in {"college fees", "fees"} and leaf in {"college fees", "fees"} and "financial" in _id_v7_norm(path).split():
        return match
    return (None, None, 0.0)


def _id_v9_analyze(self, db, user_id):
    from backend.models.document import DocumentModel

    docs = db.query(DocumentModel).filter(
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).all()
    generated = []
    for doc in docs:
        generated.extend(self.generate_suggestions_for_document(db, doc) or [])
    grouped = _ID_V9_GROUP_ANALYZE(self, db, user_id) or []
    combined = []
    seen = set()
    for item in list(generated) + list(grouped):
        item_id = getattr(item, "id", None)
        if item_id is None or item_id not in seen:
            combined.append(item)
            if item_id is not None:
                seen.add(item_id)
    return combined


def _id_v9_accept(self, db, suggestion_id, user_id, search_service=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel

    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending":
        return None
    primary = db.query(DocumentModel).filter(
        DocumentModel.id == suggestion.document_id,
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).first()
    if not primary:
        return None

    if suggestion.suggestion_type == "create_folder_group":
        evidence = _id_v7_evidence(suggestion)
        raw_ids = evidence.get("document_ids") or [primary.id]
        try:
            doc_ids = [int(value) for value in raw_ids]
        except (TypeError, ValueError):
            return None
        if len(doc_ids) < 2 or len(set(doc_ids)) != len(doc_ids):
            return None
        valid_ids = {
            int(row.id) for row in db.query(DocumentModel).filter(
                DocumentModel.id.in_(doc_ids),
                DocumentModel.owner_id == user_id,
                DocumentModel.is_deleted == 0,
            ).all()
        }
        if valid_ids != set(doc_ids):
            # Stale/deleted/cross-user members invalidate the whole proposal;
            # never partially organize a group.
            return None

        mode = str(evidence.get("target_mode") or "new")
        target_id = evidence.get("target_folder_id")
        parent_id = evidence.get("target_parent_id")
        if mode == "existing":
            if not target_id:
                return None
            target = db.query(FolderModel).filter(
                FolderModel.id == int(target_id), FolderModel.owner_id == user_id
            ).first()
            if not target:
                return None
        elif parent_id is not None:
            # If the approved parent was deleted or belongs to someone else,
            # do not silently fall back to creating a root-level folder.
            parent = db.query(FolderModel).filter(
                FolderModel.id == int(parent_id), FolderModel.owner_id == user_id
            ).first()
            if not parent:
                return None

    return _ID_V9_ORIGINAL_ACCEPT(self, db, suggestion_id, user_id, search_service)


OrganizationService._save_or_update_suggestion = _id_v9_save_or_update
OrganizationService._infer_contextual_tags = _id_v9_tags
OrganizationService.generate_suggestions_for_document = _id_v9_generate
OrganizationService.analyze_library_suggestions = _id_v9_analyze
OrganizationService.accept_suggestion = _id_v9_accept
_id_v7_upsert_group = _id_v9_upsert_group
_id_v7_match_existing = _id_v9_match_existing

# === IntelliDocs Single-Document Name+Folder Suggestions V10 ===
# Preserve existing categorization/tag/security generation, but make the
# filename recommendation stable and attach a human-approved destination folder.
import json as _id_v10_json
import re as _id_v10_re
from sqlalchemy import and_ as _id_v10_and

_ID_V10_BASE_GENERATE = _ID_V9_ORIGINAL_GENERATE  # original class method; bypass V6 rename churn
_ID_V10_PREVIOUS_SAVE = OrganizationService._save_or_update_suggestion
_ID_V10_PREVIOUS_ACCEPT = OrganizationService.accept_suggestion

_ID_V10_GOOD_DESTINATION_LABELS = {
    "college fees", "fees", "bank statements", "bills invoices",
    "dsa assignments", "academic assignments", "certificates",
    "career documents", "identity documents", "legal documents",
}

def _id_v10_folder_maps(db, user_id):
    from backend.models.folder import FolderModel
    rows = db.query(FolderModel).filter(FolderModel.owner_id == user_id).all()
    return {int(row.id): row for row in rows}

def _id_v10_folder_path(folder_id, folders):
    try:
        return _id_v7_path(int(folder_id), folders) if folder_id else ""
    except (TypeError, ValueError):
        return ""

def _id_v10_target_folder(db, doc):
    """Return a conservative, owner-scoped destination recommendation."""
    from backend.models.folder import FolderModel
    folders = _id_v10_folder_maps(db, doc.owner_id)
    if getattr(doc, "folder_id", None) and int(doc.folder_id) in folders:
        path = _id_v10_folder_path(doc.folder_id, folders)
        folder = folders[int(doc.folder_id)]
        return {
            "destination_mode": "keep_current",
            "destination_folder_id": int(folder.id),
            "destination_parent_id": folder.parent_id,
            "destination_folder_name": str(folder.name),
            "destination_folder_path": path or str(folder.name),
            "destination_reason": "This document is already stored in this folder; approval will keep its current location.",
        }

    ctx = _id_v7_context(doc)
    category = str(ctx.get("category") or getattr(doc, "category", None) or "General").strip()
    category_norm = _id_v7_norm(category)
    label = str(ctx.get("label") or "").strip()
    label_norm = _id_v7_norm(label)
    good_label = bool(ctx.get("strong")) and label_norm in _ID_V10_GOOD_DESTINATION_LABELS
    desired = label if good_label else (category if category_norm not in {"", "general", "uncategorized"} else "To Review")
    desired = _id_v10_re.sub(r"[\\/:*?\"<>|]+", " ", desired).strip(" .")[:64]
    if not desired:
        desired = "To Review"

    # Existing category root, if any. Never use another user's folder.
    category_roots = [f for f in folders.values() if f.parent_id is None and _id_v7_norm(f.name) == category_norm]
    category_root = sorted(category_roots, key=lambda f: int(f.id))[0] if category_roots else None

    candidates = [f for f in folders.values() if _id_v7_norm(f.name) == _id_v7_norm(desired)]
    if candidates:
        # Prefer the exact contextual folder under the matching category, then a
        # matching path, then a root folder. No fuzzy matching for single documents.
        candidates.sort(key=lambda f: (
            0 if category_root and f.parent_id == category_root.id else 1,
            0 if category_norm and category_norm in _id_v7_norm(_id_v10_folder_path(f.id, folders)).split() else 1,
            0 if f.parent_id is None else 1,
            int(f.id),
        ))
        chosen = candidates[0]
        path = _id_v10_folder_path(chosen.id, folders) or str(chosen.name)
        return {
            "destination_mode": "existing",
            "destination_folder_id": int(chosen.id),
            "destination_parent_id": chosen.parent_id,
            "destination_folder_name": str(chosen.name),
            "destination_folder_path": path,
            "destination_reason": "An exact existing folder match was found.",
        }

    parent_id = int(category_root.id) if (good_label and category_root) else None
    parent_path = _id_v10_folder_path(parent_id, folders) if parent_id else ""
    path = f"{parent_path} / {desired}" if parent_path else desired
    return {
        "destination_mode": "create",
        "destination_folder_id": None,
        "destination_parent_id": parent_id,
        "destination_folder_name": desired,
        "destination_folder_path": path,
        "destination_reason": "A new folder will be created only after you approve this recommendation.",
    }

def _id_v10_save_or_update(self, db, s_repo, doc, suggestion_type, current_val,
                           suggested_val, reason, confidence, evidence):
    existing = s_repo.get_existing_for_document(doc.id, suggestion_type)
    # A resolved rename is a user's decision. Do not resurrect it merely because
    # a later library-wide analysis computes a slightly different candidate.
    if suggestion_type == "rename" and existing and existing.status in {"accepted", "rejected", "kept"}:
        return None
    return _ID_V10_PREVIOUS_SAVE(self, db, s_repo, doc, suggestion_type,
                                 current_val, suggested_val, reason, confidence, evidence)

def _id_v10_generate(self, db, doc):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.suggestion import DocumentSuggestion
    from backend.core.notification_service import NotificationService

    # Call the original multi-signal generator directly. Its category/tag and
    # sensitivity data remains available to the product/tests; the UI below
    # deliberately shows only one combined name + folder card per focused file.
    generated = _ID_V10_BASE_GENERATE(self, db, doc) or []
    repo = SuggestionRepository(db)
    old = repo.get_existing_for_document(doc.id, "rename")
    if old and old.status in {"accepted", "rejected", "kept"}:
        return [s for s in generated if getattr(s, "suggestion_type", None) != "rename"]

    current = str(getattr(doc, "display_name", None) or doc.original_name or "document")
    smart = _id_v9_smart_name(doc)
    destination = _id_v10_target_folder(db, doc)
    # Even if the current name is already good, an unorganized new document can
    # receive one combined proposal that keeps the filename and suggests a folder.
    if not smart:
        if destination.get("destination_mode") == "keep_current":
            return [s for s in generated if getattr(s, "suggestion_type", None) != "rename"]
        smart = current

    rename = repo.get_existing_for_document(doc.id, "rename")
    if rename and rename.status != "pending":
        return [s for s in generated if getattr(s, "suggestion_type", None) != "rename"]

    reason = (
        f"Suggested filename: {smart}. Destination: {destination['destination_folder_path']}. "
        "Accept applies the filename and destination together; Edit changes the filename before applying. "
        + str(destination.get("destination_reason") or "")
    )
    evidence = _id_v9_json_value(rename.evidence if rename else {})
    evidence.update({
        "status_label": "PENDING",
        "suggestion_kind": "single_document_name_and_folder",
        "document_name": str(doc.original_name or current),
        "generated_filename": smart,
        **destination,
        "reason": reason,
    })

    created = False
    if rename and rename.status == "pending":
        changed = (
            str(rename.current_value or "") != current
            or str(rename.suggested_value or "") != smart
            or _id_v9_json_value(rename.evidence) != evidence
            or str(rename.reason or "") != reason
        )
        if changed:
            rename.current_value = current
            rename.suggested_value = smart
            rename.reason = reason
            rename.confidence = max(float(rename.confidence or 0.0), 0.88)
            rename.evidence = _id_v10_json.dumps(evidence, ensure_ascii=False)
            db.add(rename)
            db.commit()
            db.refresh(rename)
    else:
        rename = repo.create(
            document_id=doc.id, suggestion_type="rename", current_value=current,
            suggested_value=smart, reason=reason, confidence=0.88, evidence=evidence
        )
        created = True

    if rename and rename.status == "pending":
        if not any(getattr(s, "id", None) == rename.id for s in generated):
            generated.append(rename)

    if created:
        try:
            NotificationService.notify(
                db, user_id=doc.owner_id, event_type="SUGGESTION_READY",
                title="AI Name & Folder Suggestion Ready",
                message=f"Review the suggested name and destination folder for '{doc.original_name}'.",
                document_id=doc.id,
            )
        except Exception:
            _ID_V9_LOG.exception("Could not notify about the name/folder suggestion for document %s", doc.id)
    return generated

def _id_v10_accept(self, db, suggestion_id, user_id, search_service=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel

    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending":
        return None
    if suggestion.suggestion_type != "rename":
        return _ID_V10_PREVIOUS_ACCEPT(self, db, suggestion_id, user_id, search_service)

    doc = db.query(DocumentModel).filter(
        DocumentModel.id == suggestion.document_id,
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).first()
    if not doc:
        return None
    evidence = _id_v9_json_value(suggestion.evidence)
    mode = str(evidence.get("destination_mode") or "").lower()
    if mode not in {"existing", "create", "keep_current"}:
        return _ID_V10_PREVIOUS_ACCEPT(self, db, suggestion_id, user_id, search_service)

    folder = None
    if mode == "existing":
        try:
            folder_id = int(evidence.get("destination_folder_id"))
        except (TypeError, ValueError):
            return None
        folder = db.query(FolderModel).filter(
            FolderModel.id == folder_id, FolderModel.owner_id == user_id
        ).first()
        if not folder:
            return None  # stale/cross-user target: do not silently move to root
        doc.folder_id = folder.id
    elif mode == "create":
        folder_name = _id_v10_re.sub(r"[\\/:*?\"<>|]+", " ", str(evidence.get("destination_folder_name") or "")).strip(" .")[:64]
        if not folder_name:
            return None
        parent_id = evidence.get("destination_parent_id")
        if parent_id is not None:
            try:
                parent_id = int(parent_id)
            except (TypeError, ValueError):
                return None
            parent = db.query(FolderModel).filter(
                FolderModel.id == parent_id, FolderModel.owner_id == user_id
            ).first()
            if not parent:
                return None  # stale/cross-user parent: do not silently create at root
        query = db.query(FolderModel).filter(
            FolderModel.owner_id == user_id, FolderModel.name == folder_name
        )
        query = query.filter(FolderModel.parent_id.is_(None)) if parent_id is None else query.filter(FolderModel.parent_id == parent_id)
        folder = query.first()
        if not folder:
            folder = FolderModel(name=folder_name, owner_id=user_id, parent_id=parent_id)
            db.add(folder)
            db.flush()
        doc.folder_id = folder.id
    # keep_current intentionally leaves doc.folder_id unchanged. Folder creation,
    # document rename/move, and suggestion resolution commit in the original accept path.
    try:
        result = _ID_V10_PREVIOUS_ACCEPT(self, db, suggestion_id, user_id, search_service)
        if not result:
            db.rollback()
        return result
    except Exception:
        db.rollback()
        raise

OrganizationService._save_or_update_suggestion = _id_v10_save_or_update
OrganizationService.generate_suggestions_for_document = _id_v10_generate
OrganizationService.accept_suggestion = _id_v10_accept

def _id_v10_analyze_library_folder_groups(self, db, user_id):
    # Use the grouping-only analyzer so upload does not recreate old file-level suggestions.
    return _ID_V9_GROUP_ANALYZE(self, db, user_id) or []

OrganizationService.analyze_library_folder_groups = _id_v10_analyze_library_folder_groups



# === IntelliDocs Smart Filing V12 ===
# One recommendation per selected document: meaningful filename + category-rooted
# storage folder. The UI shows only this combined proposal, not tag/category/sensitivity cards.
import json as _id_v12_json
import re as _id_v12_re

_ID_V12_CATEGORIES = {
    "Academic", "Certificate", "Assignment", "Resume/CV", "Identity",
    "Financial", "Legal", "Professional", "Personal", "Project", "General",
}
_ID_V12_DESTINATION_LABELS = {
    "college fees", "bank statements", "bills and invoices", "dsa assignments",
    "academic assignments", "certificates", "career documents", "identity documents",
    "legal documents", "research papers", "study materials", "exam papers",
    "smart document organizing system", "project reports", "project proposals",
    "to review", "personal documents", "professional documents",
}
_ID_V12_NOISE_PHRASES = (
    "personal_near_duplicate", "near_duplicate", "duplicate_detection",
    "security_assessment", "keyword_based", "semantic_search", "keyword_search",
    "ai_based_organization", "document_features",
)


def _id_v12_safe_folder_name(value):
    value = _id_v12_re.sub(r"[\\/:*?\"<>|]+", " ", str(value or ""))
    return _id_v12_re.sub(r"\s+", " ", value).strip(" .-_\t")[:64]


def _id_v12_filename_stem(value):
    value = _id_v12_re.sub(r"\.[A-Za-z0-9]{1,8}$", "", str(value or ""))
    value = value.replace("_", " ").replace("-", " ")
    value = _id_v12_re.sub(r"(?i)\b(?:by|roll\s*no|roll\s*number|enrol(?:l)?ment\s*(?:no|number)|mr|mrs|ms)\b.*$", "", value)
    value = _id_v12_re.sub(r"\s+", " ", value).strip(" .-_\t")
    match = _id_v12_re.search(r'["“‘]([^"”’]{4,100})["”’]', str(value))
    if match:
        value = match.group(1).strip()
    return value[:100]


def _id_v12_context(doc):
    """Infer only defensible document categories from filename + extracted text."""
    name = str(getattr(doc, "original_name", "") or getattr(doc, "display_name", "") or "")
    text = str(getattr(doc, "extracted_text", "") or "")[:30000]
    blob = f"{name}\n{text}".lower()
    blob = _id_v12_re.sub(r"\s+", " ", blob)
    category, label, strong, signals = "General", "To Review", False, ["weak or mixed document signals"]

    if _id_v12_re.search(r"\b(fee receipt|college fees?|tuition fees?|fee payment|fees paid)\b", blob) and _id_v12_re.search(r"\b(college|university|student|tuition|receipt|payment)\b", blob):
        category, label, strong, signals = "Financial", "College Fees", True, ["college/tuition fees", "payment or receipt"]
    elif _id_v12_re.search(r"\b(bank statement|account statement|ifsc|upi transaction history|bank transactions)\b", blob):
        category, label, strong, signals = "Financial", "Bank Statements", True, ["bank or account statement"]
    elif _id_v12_re.search(r"\b(invoice|tax invoice|gst invoice|bill|amount due|tax return)\b", blob):
        category, label, strong, signals = "Financial", "Bills and Invoices", True, ["invoice, bill or tax document"]
    elif _id_v12_re.search(r"\b(dsa|data structures?|algorithms?)\b", blob) and _id_v12_re.search(r"\b(assignment|homework|problem set|submission|lab task)\b", blob):
        category, label, strong, signals = "Assignment", "DSA Assignments", True, ["data structures/algorithms", "assignment or submission"]
    elif _id_v12_re.search(r"\b(assignment|homework|problem set|coursework submission|lab assignment)\b", blob):
        category, label, strong, signals = "Assignment", "Academic Assignments", True, ["assignment or coursework"]
    elif _id_v12_re.search(r"\b(certificate|certification|credential|diploma|certificate of completion)\b", blob):
        category, label, strong, signals = "Certificate", "Certificates", True, ["certificate or credential"]
    elif _id_v12_re.search(r"\b(resume|curriculum vitae|professional profile|work experience|employment history)\b", blob):
        category, label, strong, signals = "Resume/CV", "Career Documents", True, ["resume or professional profile"]
    elif _id_v12_re.search(r"\b(aadhaar|pan card|passport|voter id|identity card|kyc document)\b", blob):
        category, label, strong, signals = "Identity", "Identity Documents", True, ["identity document"]
    elif _id_v12_re.search(r"\b(agreement|contract|non.?disclosure agreement|\bnda\b|power of attorney|terms and conditions)\b", blob):
        category, label, strong, signals = "Legal", "Legal Documents", True, ["agreement or legal document"]
    elif _id_v12_re.search(r"\b(smart document organizing system)\b", blob) or (_id_v12_re.search(r"\b(project based learning|\bpbl\b|capstone project)\b", blob) and _id_v12_re.search(r"\b(project|system|architecture|implementation|prototype|review)\b", blob)):
        category, label, strong, signals = "Project", "Smart Document Organizing System", True, ["project-based learning", "smart document organizing system"]
    elif _id_v12_re.search(r"\b(project proposal|project report|project documentation|capstone report)\b", blob):
        category, label, strong, signals = "Project", "Project Reports", True, ["project report or proposal"]
    elif _id_v12_re.search(r"\b(research paper|literature review|research methodology|abstract)\b", blob) and _id_v12_re.search(r"\b(methodology|references|literature|research|findings)\b", blob):
        category, label, strong, signals = "Academic", "Research Papers", True, ["research-paper structure"]
    elif _id_v12_re.search(r"\b(lecture notes?|study material|syllabus|course notes?|textbook chapter)\b", blob):
        category, label, strong, signals = "Academic", "Study Materials", True, ["study material or syllabus"]
    elif _id_v12_re.search(r"\b(question paper|exam paper|university examination|model paper)\b", blob):
        category, label, strong, signals = "Academic", "Exam Papers", True, ["exam or question paper"]
    elif _id_v12_re.search(r"\b(personal letter|personal diary|personal notes|family letter)\b", blob):
        category, label, strong, signals = "Personal", "Personal Documents", True, ["personal letter or notes"]
    elif _id_v12_re.search(r"\b(offer letter|experience letter|appointment letter|employment offer|professional correspondence)\b", blob):
        category, label, strong, signals = "Professional", "Professional Documents", True, ["professional correspondence"]
    else:
        # Respect a previously user-approved category, but don't trust the old
        # auto-classifier's generic Personal label as proof by itself.
        existing_category = str(getattr(doc, "category", "") or "").strip()
        existing_source = str(getattr(doc, "category_source", "") or "").strip().lower()
        if existing_category in _ID_V12_CATEGORIES and existing_source == "user_approved":
            category, label, strong, signals = existing_category, "To Review", False, ["previously user-approved category"]

    root_name = category.replace("/", " ").strip()
    return {
        "category": category,
        "category_folder_name": root_name,
        "label": label,
        "strong": bool(strong),
        "set_category": bool(strong),
        "signals": signals,
        "tokens": set(_id_v7_tokens(blob)),
        "text": blob,
        "name": name,
    }


def _id_v12_smart_name(doc):
    """Use meaningful title/content signals; never turn product feature text into a filename."""
    original = str(getattr(doc, "original_name", "") or getattr(doc, "display_name", "") or "document.pdf").strip()
    current = str(getattr(doc, "display_name", None) or original).strip()
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else str(getattr(doc, "file_type", "pdf") or "pdf").lower()
    if ext == "jpeg": ext = "jpg"
    ext = _id_v12_re.sub(r"[^a-z0-9]+", "", ext) or "pdf"
    blob = f"{original}\n{getattr(doc, 'extracted_text', '') or ''}".lower()

    # Preserve the document's named subject while dropping students' names/roll numbers.
    if "smart document organizing system" in blob and _id_v12_re.search(r"\b(project based learning|\bpbl\b|project report|review\s*\d*)\b", blob):
        candidate = f"Smart_Document_Organizing_System_PBL_Report.{ext}"
    elif _id_v12_re.search(r"\b(dsa|data structures?)\b", blob) and _id_v12_re.search(r"\b(assignment|homework|problem set|submission)\b", blob):
        candidate = f"Data_Structures_Assignment.{ext}"
    elif _id_v12_re.search(r"\b(bank statement|account statement|ifsc|upi transaction history)\b", blob):
        candidate = f"Bank_Statement.{ext}"
    elif _id_v12_re.search(r"\b(fee receipt|college fees?|tuition fees?|fee payment)\b", blob) and _id_v12_re.search(r"\b(receipt|payment|paid)\b", blob):
        candidate = f"College_Fee_Receipt.{ext}"
    elif _id_v12_re.search(r"\b(resume|curriculum vitae|\bcv\b)\b", blob):
        candidate = f"Resume_Web_Development.{ext}" if _id_v12_re.search(r"\b(html|css|javascript|web development|react|frontend)\b", blob) else f"Resume.{ext}"
    else:
        # A quoted title in the filename is a better signal than OCR keyword lists.
        stem_with_ext = original.rsplit(".", 1)[0] if "." in original else original
        quoted = _id_v12_re.search(r'["“‘]([^"”’]{5,90})["”’]', stem_with_ext)
        subject = quoted.group(1).strip() if quoted else ""
        if subject and _id_v12_re.search(r"\b(project|pbl|report|review|research)\b", blob):
            suffix = "_PBL_Report" if _id_v12_re.search(r"\b(project based learning|\bpbl\b|review\s*\d*)\b", blob) else "_Report"
            slug = "_".join(_id_v12_re.findall(r"[A-Za-z0-9]+", subject)[:8])
            candidate = f"{slug}{suffix}.{ext}" if slug else ""
        else:
            candidate = ""
        if not candidate:
            candidate = _id_v9_smart_name(doc) or ""
            low_candidate = candidate.lower().replace("-", "_")
            if any(noise in low_candidate for noise in _ID_V12_NOISE_PHRASES):
                candidate = ""
            if candidate and _id_v12_re.fullmatch(r"(?i)(?:personal|general|document|file|smart|ai|keyword|semantic|duplicate|near|security|assessment|report|project|based|search|detection)(?:_[a-z]+){0,5}\.[a-z0-9]{1,8}", candidate):
                candidate = ""
    if not candidate:
        # The name is already the least misleading label if content is too weak.
        candidate = current
    candidate = _id_v12_re.sub(r"[^A-Za-z0-9._ -]+", "", candidate)
    candidate = _id_v12_re.sub(r"\s+", "_", candidate.strip()).strip("._")
    if not candidate.lower().endswith("." + ext):
        candidate = candidate.rsplit(".", 1)[0] + f".{ext}" if "." in candidate else candidate + f".{ext}"
    return candidate[:150]


def _id_v12_target_folder(db, doc):
    """Plan a path like Project / Smart Document Organizing System without writing it yet."""
    from backend.models.folder import FolderModel
    ctx = _id_v12_context(doc)
    scope_user_id = db.info.get("suggestion_scope_user_id")
    folder_owner_id = int(scope_user_id) if scope_user_id and int(scope_user_id) != int(doc.owner_id) else int(doc.owner_id)
    folders = _id_v10_folder_maps(db, folder_owner_id)
    current_folder_id = getattr(doc, "folder_id", None)
    if folder_owner_id != int(doc.owner_id):
        from backend.core.document_view_service import get_preference
        personal_pref = get_preference(db, folder_owner_id, int(doc.id))
        current_folder_id = personal_pref.folder_id if personal_pref else None
    if current_folder_id and int(current_folder_id) in folders:
        folder = folders[int(current_folder_id)]
        path = _id_v10_folder_path(folder.id, folders) or folder.name
        return {
            "destination_mode": "keep_current", "destination_folder_id": int(folder.id),
            "destination_parent_id": folder.parent_id, "destination_parent_name": None,
            "destination_folder_name": str(folder.name), "destination_folder_path": path,
            "destination_category": ctx["category"], "destination_set_category": ctx["set_category"],
            "destination_reason": "The document already has a storage folder; approval will keep it there.",
        }

    category = ctx["category"]
    root_name = _id_v12_safe_folder_name(ctx["category_folder_name"]) or "General"
    leaf_name = _id_v12_safe_folder_name(ctx["label"]) or "To Review"
    roots = [f for f in folders.values() if f.parent_id is None and _id_v7_norm(f.name) == _id_v7_norm(root_name)]
    root = sorted(roots, key=lambda f: int(f.id))[0] if roots else None
    if root:
        children = [f for f in folders.values() if f.parent_id == root.id and _id_v7_norm(f.name) == _id_v7_norm(leaf_name)]
        if children:
            child = sorted(children, key=lambda f: int(f.id))[0]
            return {
                "destination_mode": "existing", "destination_folder_id": int(child.id),
                "destination_parent_id": root.id, "destination_parent_name": root.name,
                "destination_folder_name": str(child.name),
                "destination_folder_path": _id_v10_folder_path(child.id, folders) or f"{root.name} / {child.name}",
                "destination_category": category, "destination_set_category": ctx["set_category"],
                "destination_reason": "An exact folder already exists under the matching category folder.",
            }
        return {
            "destination_mode": "create", "destination_folder_id": None,
            "destination_parent_id": int(root.id), "destination_parent_name": str(root.name),
            "destination_folder_name": leaf_name, "destination_folder_path": f"{root.name} / {leaf_name}",
            "destination_category": category, "destination_set_category": ctx["set_category"],
            "destination_reason": "This subfolder will be created under the matching category folder only after approval.",
        }
    return {
        "destination_mode": "create", "destination_folder_id": None,
        "destination_parent_id": None, "destination_parent_name": root_name,
        "destination_folder_name": leaf_name, "destination_folder_path": f"{root_name} / {leaf_name}",
        "destination_category": category, "destination_set_category": ctx["set_category"],
        "destination_reason": f"The {root_name} category folder and its subfolder will be created only after approval.",
    }


# Preserve the existing multi-signal backend pipeline for product compatibility.
# The V12 Suggestions screen deliberately renders ONLY the combined rename/folder
# item, so category/tag/sensitivity cards do not clutter the user's review surface.
_ID_V12_BASE_GENERATE = OrganizationService.generate_suggestions_for_document


def _id_v12_generate(self, db, doc):
    """Keep legacy classification signals stored while exposing one combined UI proposal."""
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.core.notification_service import NotificationService
    base_generated = _ID_V12_BASE_GENERATE(self, db, doc) or []
    repo = SuggestionRepository(db)
    existing = repo.get_existing_for_document(doc.id, "rename")
    if existing and existing.status in {"accepted", "rejected", "kept", "edited"}:
        # A prior human choice stays resolved. Other backend suggestions remain
        # available to their existing product workflows but are not rendered here.
        return [s for s in base_generated if getattr(s, "suggestion_type", None) != "rename"]

    current = str(getattr(doc, "display_name", None) or getattr(doc, "original_name", None) or "document.pdf")
    smart = _id_v12_smart_name(doc) or current
    destination = _id_v12_target_folder(db, doc)
    if smart.casefold() == current.casefold() and destination.get("destination_mode") == "keep_current":
        return [s for s in base_generated if getattr(s, "suggestion_type", None) != "rename"]

    ctx = _id_v12_context(doc)
    evidence = _id_v9_json_value(existing.evidence if existing else {})
    evidence.update({
        "status_label": "PENDING",
        "suggestion_kind": "single_document_name_and_folder",
        "document_name": str(getattr(doc, "original_name", None) or current),
        "generated_filename": smart,
        "destination_category": destination.get("destination_category", ctx["category"]),
        "destination_set_category": bool(destination.get("destination_set_category", ctx["set_category"])),
        "filing_signals": ctx["signals"],
        **destination,
    })
    mode_note = "The matching category folder and subfolder will be created after approval." if destination.get("destination_mode") == "create" else destination.get("destination_reason", "")
    reason = f"Content signals: {', '.join(ctx['signals'][:3])}. Suggested destination: {destination['destination_folder_path']}. Nothing changes until you approve. {mode_note}"

    if existing and existing.status == "pending":
        existing.current_value = current
        existing.suggested_value = smart
        existing.reason = reason
        existing.confidence = 0.90 if ctx["strong"] else 0.70
        existing.evidence = _id_v12_json.dumps(evidence, ensure_ascii=False)
        db.add(existing)
        db.commit()
        db.refresh(existing)
        combined = list(base_generated)
        if not any(getattr(s, "id", None) == existing.id for s in combined):
            combined.append(existing)
        # Keep return values consistent with other callers; the UI filters to rename.
        return combined

    created = repo.create(
        document_id=doc.id, suggestion_type="rename", current_value=current,
        suggested_value=smart, reason=reason,
        confidence=0.90 if ctx["strong"] else 0.70, evidence=evidence,
    )
    try:
        NotificationService.notify(
            db, user_id=doc.owner_id, event_type="SUGGESTION_READY",
            title="Smart File Name & Folder Ready",
            message=f"Review the name and category folder for '{doc.original_name}'.",
            document_id=doc.id,
        )
    except Exception:
        try: _ID_V9_LOG.exception("Could not notify about V12 suggestion for document %s", doc.id)
        except Exception: pass
    combined = list(base_generated)
    if not any(getattr(s, "id", None) == created.id for s in combined):
        combined.append(created)
    return combined


_ID_V12_BASE_ACCEPT = OrganizationService.accept_suggestion

def _id_v12_accept(self, db, suggestion_id, user_id, search_service=None):
    """Create missing category parent + subfolder transactionally, then apply the name."""
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel
    from backend.models.category import CategoryModel
    from backend.core.audit_service import AuditService

    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending" or suggestion.suggestion_type != "rename":
        return _ID_V12_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)
    doc = db.query(DocumentModel).filter(
        DocumentModel.id == suggestion.document_id,
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).first()
    if not doc:
        return None
    evidence = _id_v9_json_value(suggestion.evidence)
    mode = str(evidence.get("destination_mode") or "").lower()
    if mode == "create":
        parent_id = evidence.get("destination_parent_id")
        parent_name = _id_v12_safe_folder_name(evidence.get("destination_parent_name"))
        if parent_id is None and parent_name:
            root = db.query(FolderModel).filter(
                FolderModel.owner_id == user_id, FolderModel.parent_id.is_(None)
            ).all()
            root = next((f for f in root if _id_v7_norm(f.name) == _id_v7_norm(parent_name)), None)
            if not root:
                root = FolderModel(name=parent_name, owner_id=user_id, parent_id=None)
                db.add(root)
                db.flush()
            parent_id = int(root.id)
            evidence["destination_parent_id"] = parent_id
            evidence["destination_parent_name"] = root.name
            evidence["destination_folder_path"] = f"{root.name} / {evidence.get('destination_folder_name', 'To Review')}"
            suggestion.evidence = _id_v12_json.dumps(evidence, ensure_ascii=False)
            db.add(suggestion)
            db.flush()
        elif parent_id is not None:
            parent = db.query(FolderModel).filter(
                FolderModel.id == int(parent_id), FolderModel.owner_id == user_id
            ).first()
            if not parent:
                return None  # stale/cross-user target: fail closed

    result = _ID_V12_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)
    if not result:
        return None

    if evidence.get("destination_set_category"):
        category_name = str(evidence.get("destination_category") or "General").strip()
        category = db.query(CategoryModel).filter(
            CategoryModel.name == category_name,
            ((CategoryModel.is_system == 1) | (CategoryModel.owner_id == user_id)),
        ).first()
        doc = db.query(DocumentModel).filter(DocumentModel.id == suggestion.document_id, DocumentModel.owner_id == user_id).first()
        if doc:
            doc.category = category_name
            doc.category_source = "user_approved"
            doc.category_id = int(category.id) if category else None
            db.add(doc)
            db.commit()
            try:
                AuditService.log(db, action="AI_SMART_FILING_CATEGORY_APPLIED", user_id=user_id,
                                 resource_type="document", resource_id=doc.uuid,
                                 detail={"category": category_name, "folder_path": evidence.get("destination_folder_path")})
            except Exception:
                db.rollback()
    return result


OrganizationService.generate_suggestions_for_document = _id_v12_generate
OrganizationService.accept_suggestion = _id_v12_accept
# Other product modules can still use tag APIs; this one-file AI review doesn't create tag clutter.
# === End IntelliDocs Smart Filing V12 ===

# === IntelliDocs Adaptive Filing & Grouping V14 ===
# V14 fixes three workflow gaps in the V12/V13 overlays:
# 1) Honor supported categories already assigned by the document classifier.
# 2) Never route a document with usable subject context to a generic "To Review" folder.
# 3) Recompute and UPSERT category-based multi-document groups on each upload, so new
#    matching documents update one pending proposal instead of creating stale cards.
import json as _id_v14_json
import re as _id_v14_re
from datetime import datetime as _id_v14_datetime, timezone as _id_v14_timezone

_ID_V14_CATEGORY_LABELS = {
    "Certificate": "Certificates",
    "Assignment": "Academic Assignments",
    "Academic": "Study Materials",
    "Resume/CV": "Career Documents",
    "Identity": "Identity Documents",
    "Financial": "Financial Documents",
    "Legal": "Legal Documents",
    "Professional": "Professional Documents",
    "Personal": "Personal Documents",
    "Project": "Project Documents",
    "General": "Unclassified Documents",
}
_ID_V14_NOISE = {
    "personal", "general", "document", "documents", "file", "files", "image", "images",
    "scan", "scanned", "copy", "final", "latest", "new", "old", "main", "page",
    "duplicate detection", "near duplicate", "semantic search", "keyword search",
    "keyword based", "security assessment", "ai based organization", "document features",
    "smart organization", "personal near duplicate", "category", "untitled", "to review",
}
_ID_V14_BOILERPLATE = (
    "detect exact, near-duplicate", "duplicate detection module", "ai & search:",
    "semantic search, keyword search", "this is to certify", "certificate of completion",
    "has successfully completed", "successfully completed the course", "awarded to",
    "certificate is awarded", "date of issue", "signature of", "roll no", "roll number",
    "enrollment number", "student name", "mobile number", "email address",
)


def _id_v14_norm(value):
    return _id_v12_re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _id_v14_current_name(doc):
    return str(getattr(doc, "display_name", None) or getattr(doc, "original_name", None) or "document")


def _id_v14_is_hash_like(value):
    stem = str(value or "").rsplit(".", 1)[0].strip().lower()
    compact = _id_v12_re.sub(r"[^a-f0-9]", "", stem)
    return bool(
        _id_v12_re.fullmatch(r"[0-9a-f]{24,}", stem.replace("-", ""))
        or _id_v12_re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stem)
        or (len(compact) >= 22 and len(compact) / max(1, len(stem.replace("-", "").replace("_", ""))) > 0.9)
    )


def _id_v14_clean_subject(value):
    value = str(value or "").replace("\u200b", " ").strip()
    value = _id_v12_re.sub(r"(?i)\b(?:roll\s*no\.?|roll\s*number|enrol(?:l)?ment\s*(?:no\.?|number)|student\s*name|mobile\s*(?:no\.?|number)|email)\b.*$", "", value)
    value = _id_v12_re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", " ", value, flags=_id_v12_re.I)
    value = _id_v12_re.sub(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)", " ", value)
    words = _id_v12_re.findall(r"[A-Za-z][A-Za-z0-9+#.-]{1,30}|\d{2,4}", value)
    words = [w.strip("._- ") for w in words if w.strip("._- ")]
    if not words:
        return ""
    if len(words) == 1 and words[0].lower() in _ID_V14_NOISE:
        return ""
    compact = " ".join(words).strip()
    if _id_v14_norm(compact) in _ID_V14_NOISE:
        return ""
    if len(compact) < 4 or len(compact) > 90:
        return ""
    return compact[:90]


def _id_v14_content_subject(doc):
    """Pick a title-like phrase from extracted text/topics without using generic summaries."""
    original = str(getattr(doc, "original_name", "") or "")
    extracted = str(getattr(doc, "extracted_text", "") or "")
    summary = str(getattr(doc, "summary", "") or "")
    if summary and any(p in summary.lower() for p in _ID_V14_BOILERPLATE):
        summary = ""

    # Certificate/course titles are often found near completion language in OCR.
    if extracted:
        lines = [_id_v12_re.sub(r"\s+", " ", line).strip(" \t-:|•*#") for line in extracted.splitlines()[:120]]
        topic_words = {"cloud", "infrastructure", "tensorflow", "python", "javascript", "security", "network", "networking", "machine", "learning", "data", "structures", "algorithm", "web", "development", "artificial", "intelligence", "design", "architecture", "project", "organizing", "system", "database", "engineering", "finance", "accounting", "marketing", "physics", "chemistry", "biology", "mathematics", "statistics", "research", "analysis", "report", "assignment", "certificate", "ai", "ml", "dsa", "html", "css", "java", "c++"}
        for i, line in enumerate(lines):
            low = line.lower()
            if not line or len(line) < 5 or len(line) > 100:
                continue
            if any(noise in low for noise in _ID_V14_BOILERPLATE):
                # Sometimes the title is on the following line.
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    nxt = _id_v14_clean_subject(next_line)
                    nxt_words = set(_id_v14_norm(nxt).split())
                    # Skip a recipient's two-word name if it sits immediately below the certificate heading.
                    likely_person = len(nxt_words) <= 2 and not (nxt_words & topic_words) and not _id_v12_re.search(r"\b(to|for|of|in|and|with|from)\b", nxt.lower())
                    if nxt and not likely_person and not any(n in nxt.lower() for n in _ID_V14_BOILERPLATE):
                        return nxt
                continue
            if _id_v12_re.search(r"(?i)\b(?:name|candidate|student|recipient|awarded to|issued to|roll|registration|signature|date|certificate number)\b", line):
                continue
            candidate = _id_v14_clean_subject(line)
            if not candidate:
                continue
            norm = _id_v14_norm(candidate)
            candidate_words = set(norm.split())
            likely_person = len(candidate_words) <= 2 and not (candidate_words & topic_words) and not _id_v12_re.search(r"\b(to|for|of|in|and|with|from)\b", norm)
            if likely_person:
                continue
            if norm in _ID_V14_NOISE or any(noise in norm for noise in ("duplicate detection", "semantic search", "keyword search", "security assessment")):
                continue
            # Favor concise, title-like lines containing recognizable topical nouns.
            if len(candidate.split()) >= 2 and re.search(r"[A-Za-z]{3}", candidate):
                return candidate

    topics = getattr(doc, "key_topics", None)
    if isinstance(topics, str):
        try:
            topics = _id_v14_json.loads(topics)
        except Exception:
            topics = []
    for topic in topics or []:
        candidate = _id_v14_clean_subject(topic)
        if candidate and _id_v14_norm(candidate) not in _ID_V14_NOISE:
            if not any(n in candidate.lower() for n in ("duplicate detection", "semantic search", "keyword search", "security assessment")):
                return candidate

    # Summary is only a fallback if it is not a known product-feature boilerplate.
    if summary:
        first = _id_v12_re.split(r"(?<=[.!?])\s+", summary.strip(), maxsplit=1)[0]
        candidate = _id_v14_clean_subject(first)
        if candidate and _id_v14_norm(candidate) not in _ID_V14_NOISE and not any(p in first.lower() for p in _ID_V14_BOILERPLATE):
            return candidate
    return ""


def _id_v14_subject(doc):
    """Best non-PII folder label: strong V12 name, human filename, topics, or OCR title."""
    original = str(getattr(doc, "original_name", None) or "")
    current = _id_v14_current_name(doc)
    smart = str(_id_v12_smart_name(doc) or "").strip()
    for candidate_name in (smart, current, original):
        if not candidate_name:
            continue
        stem = candidate_name.rsplit(".", 1)[0] if "." in candidate_name else candidate_name
        if _id_v14_is_hash_like(stem):
            continue
        candidate = _id_v14_clean_subject(stem.replace("_", " ").replace("-", " "))
        if candidate and _id_v14_norm(candidate) not in _ID_V14_NOISE:
            return candidate
    return _id_v14_content_subject(doc)


def _id_v14_context(doc):
    """Prefer strong document-content signals; honor a valid existing classifier category."""
    base = _id_v12_context(doc)
    ctx = dict(base)
    category = str(base.get("category") or "General").strip()
    label = str(base.get("label") or "").strip()
    strong = bool(base.get("strong"))
    current_category = str(getattr(doc, "category", None) or "").strip()
    source = str(getattr(doc, "category_source", None) or "").strip().lower()
    known_categories = set(_ID_V12_CATEGORIES)

    # Explicit content rules outrank classifier output. When those rules are weak,
    # preserve the existing supported category instead of collapsing everything to General.
    if not strong and current_category in known_categories and current_category != "General":
        category = current_category
        # Certificates belong to one shared category folder even when the course
        # titles differ; their filenames still retain each specific course title.
        label = (_ID_V14_CATEGORY_LABELS.get(category, "Documents") if category == "Certificate"
                 else (_id_v14_subject(doc) or _ID_V14_CATEGORY_LABELS.get(category, "Documents")))
        ctx["signals"] = [f"existing classifier category: {category}"]
        ctx["set_category"] = False
    elif not strong and category == "General":
        category = "General"
        label = _id_v14_subject(doc) or (
            "Unclassified Images" if str(getattr(doc, "file_type", "")).lower() in {"image", "jpg", "jpeg", "png", "webp", "bmp", "tiff"}
            else "Unclassified Documents"
        )
        ctx["signals"] = ["meaningful title/filename fallback" if label not in {"Unclassified Images", "Unclassified Documents"} else "no reliable document-type signal"]
        ctx["set_category"] = False
    if not label or _id_v14_norm(label) in {"to review", "general", "document", "file"}:
        label = _id_v14_subject(doc) or _ID_V14_CATEGORY_LABELS.get(category, "Unclassified Documents")
    ctx.update({
        "category": category,
        "category_folder_name": category.replace("/", " ").strip(),
        "label": _id_v12_safe_folder_name(label) or _ID_V14_CATEGORY_LABELS.get(category, "Unclassified Documents"),
        "strong": bool(strong),
        "groupable": bool(strong or (category in known_categories and category != "General" and source not in {"", "system_default", "default", "unknown"})),
        "set_category": bool(ctx.get("set_category", strong)),
    })
    return ctx


def _id_v14_smart_name(doc):
    """Use a real course/title for certificates and assignments before generic OCR filenames."""
    current = _id_v14_current_name(doc)
    original = str(getattr(doc, "original_name", None) or current)
    base = str(_id_v12_smart_name(doc) or current).strip()
    category = str(getattr(doc, "category", None) or "General").strip()
    if category not in _ID_V12_CATEGORIES:
        category = "General"
    blob = f"{original}\n{getattr(doc, 'extracted_text', '') or ''}".lower()
    subject = _id_v14_content_subject(doc)
    # Prefer a course/credential title over generic outputs such as Certificate_And_Completion.
    # This also ensures two different certificates receive different useful filenames.
    category_is_certificate = category == "Certificate" or bool(_id_v12_re.search(r"\b(certificate|certification|credential|diploma)\b", blob))
    category_is_assignment = category == "Assignment" or bool(_id_v12_re.search(r"\b(assignment|homework|problem set|coursework submission)\b", blob))
    if subject and (category_is_certificate or category_is_assignment):
        slug = "_".join(_id_v12_re.findall(r"[A-Za-z0-9]+", subject)[:8])
        if slug:
            ext = original.rsplit(".", 1)[-1].lower() if "." in original else str(getattr(doc, "file_type", "pdf") or "pdf").lower()
            if ext == "jpeg": ext = "jpg"
            ext = _id_v12_re.sub(r"[^a-z0-9]+", "", ext) or "pdf"
            if category_is_certificate and "certificate" not in slug.lower():
                slug += "_Certificate"
            elif category_is_assignment and "assignment" not in slug.lower():
                slug += "_Assignment"
            return f"{slug}.{ext}"[:150]
    if base and base.casefold() != current.casefold() and not _id_v14_is_hash_like(base):
        if _id_v14_norm(base.rsplit(".", 1)[0]) not in _ID_V14_NOISE:
            return base
    if subject:
        slug = "_".join(_id_v12_re.findall(r"[A-Za-z0-9]+", subject)[:8])
        if slug:
            ext = original.rsplit(".", 1)[-1].lower() if "." in original else str(getattr(doc, "file_type", "pdf") or "pdf").lower()
            if ext == "jpeg": ext = "jpg"
            ext = _id_v12_re.sub(r"[^a-z0-9]+", "", ext) or "pdf"
            return f"{slug}.{ext}"[:150]
    # If a filename is already human-readable, do not rename it for the sake of renaming.
    stem = current.rsplit(".", 1)[0] if "." in current else current
    if not _id_v14_is_hash_like(stem) and _id_v14_norm(stem) not in _ID_V14_NOISE:
        return base or current
    # No usable text/title was extracted. Preserve original; never fabricate a false topic.
    return current


def _id_v14_target_folder(db, doc, ctx=None):
    """Use an existing category folder or propose a subject-specific child under it."""
    from backend.models.folder import FolderModel
    ctx = ctx or _id_v14_context(doc)
    folders = _id_v10_folder_maps(db, doc.owner_id)
    current_folder_id = getattr(doc, "folder_id", None)
    if current_folder_id and int(current_folder_id) in folders:
        folder = folders[int(current_folder_id)]
        path = _id_v10_folder_path(folder.id, folders) or folder.name
        return {
            "destination_mode": "keep_current", "destination_folder_id": int(folder.id),
            "destination_parent_id": folder.parent_id, "destination_parent_name": None,
            "destination_folder_name": str(folder.name), "destination_folder_path": path,
            "destination_category": ctx["category"], "destination_set_category": ctx["set_category"],
            "destination_reason": "This document already has a storage folder; approval keeps it there.",
        }
    category = str(ctx["category"] or "General")
    root_name = _id_v12_safe_folder_name(ctx.get("category_folder_name") or category.replace("/", " ")) or "General"
    leaf_name = _id_v12_safe_folder_name(ctx.get("label") or _ID_V14_CATEGORY_LABELS.get(category, "Unclassified Documents")) or "Unclassified Documents"
    roots = [f for f in folders.values() if f.parent_id is None and _id_v14_norm(f.name) == _id_v14_norm(root_name)]
    root = sorted(roots, key=lambda f: int(f.id))[0] if roots else None
    if root:
        children = [f for f in folders.values() if f.parent_id == root.id and _id_v14_norm(f.name) == _id_v14_norm(leaf_name)]
        if children:
            child = sorted(children, key=lambda f: int(f.id))[0]
            return {
                "destination_mode": "existing", "destination_folder_id": int(child.id),
                "destination_parent_id": int(root.id), "destination_parent_name": str(root.name),
                "destination_folder_name": str(child.name), "destination_folder_path": _id_v10_folder_path(child.id, folders) or f"{root.name} / {child.name}",
                "destination_category": category, "destination_set_category": ctx["set_category"],
                "destination_reason": "A matching folder already exists under the document category.",
            }
        return {
            "destination_mode": "create", "destination_folder_id": None,
            "destination_parent_id": int(root.id), "destination_parent_name": str(root.name),
            "destination_folder_name": leaf_name, "destination_folder_path": f"{root.name} / {leaf_name}",
            "destination_category": category, "destination_set_category": ctx["set_category"],
            "destination_reason": "The subject-specific folder will be created under the existing category folder after approval.",
        }
    return {
        "destination_mode": "create", "destination_folder_id": None,
        "destination_parent_id": None, "destination_parent_name": root_name,
        "destination_root_name": root_name, "destination_folder_name": leaf_name,
        "destination_folder_path": f"{root_name} / {leaf_name}",
        "destination_category": category, "destination_set_category": ctx["set_category"],
        "destination_reason": f"The {root_name} category folder and its subject folder are created only after approval.",
    }


_ID_V14_BASE_GENERATE = OrganizationService.generate_suggestions_for_document
_ID_V14_BASE_ACCEPT = OrganizationService.accept_suggestion
_ID_V14_BASE_GROUP_ANALYZE = OrganizationService.analyze_library_folder_groups


def _id_v14_generate(self, db, doc):
    """Preserve original pipelines but upsert one pending name + destination proposal."""
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    generated = _ID_V14_BASE_GENERATE(self, db, doc) or []
    repo = SuggestionRepository(db)
    suggestion = repo.get_existing_for_document(doc.id, "rename")
    if not suggestion or suggestion.status != "pending":
        return [s for s in generated if getattr(s, "suggestion_type", None) != "rename"] + ([suggestion] if suggestion and suggestion.status == "pending" else [])

    current = _id_v14_current_name(doc)
    ctx = _id_v14_context(doc)
    smart = _id_v14_smart_name(doc) or current
    destination = _id_v14_target_folder(db, doc, ctx)
    evidence = _id_v9_json_value(suggestion.evidence)
    evidence.update({
        "status_label": "PENDING",
        "suggestion_kind": "single_document_name_and_folder",
        "v14_smart_filing": True,
        "document_name": str(getattr(doc, "original_name", None) or current),
        "generated_filename": smart,
        "destination_category": destination.get("destination_category", ctx["category"]),
        "destination_set_category": bool(destination.get("destination_set_category", ctx["set_category"])),
        "filing_signals": list(ctx.get("signals") or [])[:5],
        **destination,
    })
    reason = (
        f"Document type: {ctx['category']}. Filing signals: {', '.join(ctx.get('signals') or []) or 'document title and extracted content'}. "
        f"Suggested destination: {destination['destination_folder_path']}. "
        "Apply Name & Folder approves both together; no change is made before approval."
    )
    changed = (
        str(suggestion.current_value or "") != current
        or str(suggestion.suggested_value or "") != smart
        or _id_v9_json_value(suggestion.evidence) != evidence
        or str(suggestion.reason or "") != reason
    )
    if changed:
        suggestion.current_value = current
        suggestion.suggested_value = smart
        suggestion.reason = reason
        suggestion.confidence = 0.92 if ctx.get("strong") else (0.80 if ctx.get("groupable") else 0.70)
        suggestion.evidence = _id_v12_json.dumps(evidence, ensure_ascii=False)
        db.add(suggestion)
        db.commit()
        db.refresh(suggestion)
    combined = [s for s in generated if getattr(s, "suggestion_type", None) != "rename"]
    combined.append(suggestion)
    return combined


def _id_v14_folder_plan(db, user_id, category, label):
    from backend.models.folder import FolderModel
    root_name = _id_v12_safe_folder_name(str(category or "General").replace("/", " ")) or "General"
    leaf_name = _id_v12_safe_folder_name(label) or _ID_V14_CATEGORY_LABELS.get(category, "Unclassified Documents")
    folders = db.query(FolderModel).filter(FolderModel.owner_id == user_id).all()
    roots = [f for f in folders if f.parent_id is None and _id_v14_norm(f.name) == _id_v14_norm(root_name)]
    root = sorted(roots, key=lambda f: int(f.id))[0] if roots else None
    if root:
        child = next((f for f in folders if f.parent_id == root.id and _id_v14_norm(f.name) == _id_v14_norm(leaf_name)), None)
        if child:
            return {"target_mode": "existing", "target_folder_id": int(child.id), "target_parent_id": int(root.id), "target_folder_path": _id_v10_folder_path(child.id, {f.id:f for f in folders}) or f"{root.name} / {child.name}", "destination_root_name": root_name}
        return {"target_mode": "new", "target_folder_id": None, "target_parent_id": int(root.id), "target_folder_path": f"{root.name} / {leaf_name}", "destination_root_name": root_name}
    return {"target_mode": "new", "target_folder_id": None, "target_parent_id": None, "target_folder_path": f"{root_name} / {leaf_name}", "destination_root_name": root_name}


def _id_v14_group_analyze(self, db, user_id):
    """Analyze category/context clusters; update one pending group when a new doc arrives."""
    from backend.models.document import DocumentModel
    from backend.models.suggestion import DocumentSuggestion
    from backend.database.repositories.suggestion_repo import SuggestionRepository

    docs = db.query(DocumentModel).filter(
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
    ).all()
    contexts = {}
    clusters = {}
    for doc in docs:
        ctx = _id_v14_context(doc)
        contexts[int(doc.id)] = ctx
        category = str(ctx.get("category") or "General")
        label = str(ctx.get("label") or "").strip()
        if not label or not ctx.get("groupable"):
            continue
        key = (_id_v14_norm(category), _id_v14_norm(label))
        clusters.setdefault(key, {"category": category, "label": label, "docs": []})["docs"].append(doc)

    all_group_suggestions = db.query(DocumentSuggestion).join(
        DocumentModel, DocumentSuggestion.document_id == DocumentModel.id
    ).filter(
        DocumentModel.owner_id == user_id,
        DocumentModel.is_deleted == 0,
        DocumentSuggestion.suggestion_type == "create_folder_group",
    ).order_by(DocumentSuggestion.created_at.desc()).all()

    generated = []
    for (cat_norm, label_norm), cluster in clusters.items():
        members = sorted(cluster["docs"], key=lambda d: int(d.id))
        if len(members) < 2:
            continue
        category, label = cluster["category"], cluster["label"]
        doc_ids = [int(d.id) for d in members]
        ids_signature = sorted(doc_ids)
        plan = _id_v14_folder_plan(db, user_id, category, label)
        target_id = plan.get("target_folder_id")
        actionable = any(int(getattr(d, "folder_id", 0) or 0) != int(target_id or 0) for d in members) if target_id else True
        key = f"v14:{cat_norm}:{label_norm}"

        matching = []
        for prior in all_group_suggestions:
            ev = _id_v9_json_value(prior.evidence)
            if ev.get("v14_group_key") == key:
                matching.append((prior, ev))
                continue
            old_cat = _id_v14_norm(ev.get("suggested_category") or ev.get("category") or "")
            old_label = _id_v14_norm(ev.get("suggested_folder_name") or ev.get("label") or "")
            if old_cat == cat_norm and old_label == label_norm:
                matching.append((prior, ev))

        # A completed decision applies to its exact document set, but a new upload
        # changes the membership signature and therefore warrants a fresh proposal.
        exact_resolved = False
        for prior, ev in matching:
            try: previous_ids = sorted(int(x) for x in (ev.get("document_ids") or []))
            except Exception: previous_ids = []
            if prior.status != "pending" and previous_ids == ids_signature:
                exact_resolved = True
                break

        pending = [(prior, ev) for prior, ev in matching if prior.status == "pending"]
        if not actionable:
            # Everything is already in the correct destination. Close stale pending cards.
            for prior, ev in pending:
                prior.status = "kept"
                prior.resolved_at = _id_v14_datetime.now(_id_v14_timezone.utc).isoformat()
                prior.resolved_by = user_id
                ev["v14_auto_closed_reason"] = "All matching documents already reside in the recommended folder."
                prior.evidence = _id_v14_json.dumps(ev, ensure_ascii=False)
                db.add(prior)
            continue
        if exact_resolved:
            # Do not resurrect a proposal the user already resolved for this same set.
            for prior, ev in pending:
                prior.status = "rejected"
                prior.resolved_at = _id_v14_datetime.now(_id_v14_timezone.utc).isoformat()
                prior.resolved_by = user_id
                ev["v14_superseded"] = True
                prior.evidence = _id_v14_json.dumps(ev, ensure_ascii=False)
                db.add(prior)
            continue

        evidence = {
            "v14_group_key": key,
            "v14_strong_group": True,
            "v14_membership_ids": ids_signature,
            "document_ids": ids_signature,
            "document_names": [str(getattr(d, "display_name", None) or d.original_name) for d in members],
            "category": category,
            "suggested_category": category,
            "suggested_folder_name": label,
            "target_mode": plan["target_mode"],
            "target_folder_id": plan.get("target_folder_id"),
            "target_parent_id": plan.get("target_parent_id"),
            "target_folder_path": plan["target_folder_path"],
            "destination_root_name": plan.get("destination_root_name"),
            "shared_signals": sorted({s for d in members for s in contexts[int(d.id)].get("signals", [])})[:8],
            "strong_context": True,
            "status_label": "PENDING",
        }
        existing_folder_note = "An existing matching category folder will be reused." if plan["target_mode"] == "existing" else "The folder path will be created only after approval."
        reason = f"{len(members)} documents share the {category} document context '{label}'. {existing_folder_note} New matching uploads update this pending proposal instead of adding duplicate cards."

        if pending:
            pending.sort(key=lambda item: str(getattr(item[0], "created_at", "")), reverse=True)
            target_suggestion, _ = pending[0]
            for duplicate, duplicate_ev in pending[1:]:
                duplicate.status = "rejected"
                duplicate.resolved_at = _id_v14_datetime.now(_id_v14_timezone.utc).isoformat()
                duplicate.resolved_by = user_id
                duplicate_ev["v14_superseded_by"] = int(target_suggestion.id)
                duplicate.evidence = _id_v14_json.dumps(duplicate_ev, ensure_ascii=False)
                db.add(duplicate)
            target_suggestion.document_id = int(members[0].id)
            target_suggestion.current_value = "Unorganized"
            target_suggestion.suggested_value = plan["target_folder_path"]
            target_suggestion.reason = reason
            target_suggestion.confidence = 0.92
            target_suggestion.evidence = _id_v12_json.dumps(evidence, ensure_ascii=False)
            db.add(target_suggestion)
            db.commit()
            db.refresh(target_suggestion)
            generated.append(target_suggestion)
        else:
            repo = SuggestionRepository(db)
            created = repo.create(
                document_id=int(members[0].id),
                suggestion_type="create_folder_group",
                current_value="Unorganized",
                suggested_value=plan["target_folder_path"],
                reason=reason,
                confidence=0.92,
                evidence=evidence,
            )
            generated.append(created)

    db.commit()
    return generated


def _id_v14_accept(self, db, suggestion_id, user_id, search_service=None):
    """Ensure the proposed category root exists only at user approval time."""
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.folder import FolderModel
    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending" or suggestion.suggestion_type != "create_folder_group":
        return _ID_V14_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)
    ev = _id_v9_json_value(suggestion.evidence)
    if ev.get("v14_group_key") and str(ev.get("target_mode") or "new") != "existing" and not ev.get("target_parent_id"):
        root_name = _id_v12_safe_folder_name(ev.get("destination_root_name") or str(ev.get("category") or "General").replace("/", " ")) or "General"
        roots = db.query(FolderModel).filter(FolderModel.owner_id == user_id, FolderModel.parent_id.is_(None)).all()
        root = next((f for f in roots if _id_v14_norm(f.name) == _id_v14_norm(root_name)), None)
        if not root:
            root = FolderModel(name=root_name, owner_id=user_id, parent_id=None)
            db.add(root)
            db.flush()
        ev["target_parent_id"] = int(root.id)
        ev["destination_root_name"] = root_name
        suggestion.evidence = _id_v12_json.dumps(ev, ensure_ascii=False)
        db.add(suggestion)
        db.flush()
    try:
        result = _ID_V14_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)
        if not result:
            db.rollback()
        return result
    except Exception:
        db.rollback()
        raise


OrganizationService.generate_suggestions_for_document = _id_v14_generate
OrganizationService.analyze_library_folder_groups = _id_v14_group_analyze
OrganizationService.accept_suggestion = _id_v14_accept
# === End IntelliDocs Adaptive Filing & Grouping V14 ===



# === IntelliDocs Smart Filing Lifecycle V18 ===
# Folder routing is a separate, actionable decision from filename naming.
# Group suggestions remain independent and use the same category-rooted paths.
import json as _id_v18_json
import re as _id_v18_re
from datetime import datetime as _id_v18_datetime, timezone as _id_v18_timezone

_ID_V18_BASE_GENERATE = OrganizationService.generate_suggestions_for_document
_ID_V18_BASE_ACCEPT = OrganizationService.accept_suggestion
_ID_V18_BASE_CONTEXT = _id_v14_context
_ID_V18_BASE_CONTENT_SUBJECT = _id_v14_content_subject
_ID_V18_BASE_GROUP_ANALYZE = OrganizationService.analyze_library_folder_groups


def _id_v18_content_subject(doc):
    candidate = str(_ID_V18_BASE_CONTENT_SUBJECT(doc) or "").strip()
    file_type = str(getattr(doc, "file_type", "") or "").lower()
    original = str(getattr(doc, "original_name", "") or "")
    if file_type in {"image", "jpg", "jpeg", "png", "webp", "bmp", "tiff"} or _id_v14_is_hash_like(original.rsplit(".", 1)[0]):
        # Turn vision captions into filing subjects, not captions-as-filenames.
        candidate = _id_v18_re.sub(
            r"^(?:(?:a|an|the)\s+)?(?:close[- ]up(?:\s+view)?\s+of|image\s+of|photo(?:graph)?\s+of|picture\s+of|screenshot\s+of|drawing\s+of|painting\s+of|view\s+of)\s+(?:(?:a|an|the)\s+)?",
            "", candidate, flags=_id_v18_re.I,
        ).strip(" .,:;-_")
        candidate = _id_v18_re.sub(r"^(?:a|an|the)\s+", "", candidate, flags=_id_v18_re.I).strip()
        if candidate:
            # Natural title casing makes both the filename and destination readable.
            words = candidate.split()
            candidate = " ".join(w.upper() if w.lower() in {"ai", "ml", "dsa", "html", "css", "pdf"} else w[:1].upper() + w[1:] for w in words)
    return candidate


# Existing name/context helpers resolve `_id_v14_content_subject` dynamically.
_id_v14_content_subject = _id_v18_content_subject


def _id_v18_clean_path_part(value):
    value = _id_v18_re.sub(r"[\\/:*?\"<>|]+", " ", str(value or ""))
    value = _id_v18_re.sub(r"\s+", " ", value).strip(" .-_	")
    if value in {".", ".."}:
        return ""
    return value[:64]


def _id_v18_find_or_create_folder(db, user_id, name, parent_id=None, create=False):
    from backend.models.folder import FolderModel
    safe = _id_v18_clean_path_part(name)
    if not safe:
        return None
    query = db.query(FolderModel).filter(FolderModel.owner_id == user_id)
    query = query.filter(FolderModel.parent_id.is_(None)) if parent_id is None else query.filter(FolderModel.parent_id == int(parent_id))
    rows = query.all()
    folder = next((f for f in rows if _id_v14_norm(f.name) == _id_v14_norm(safe)), None)
    if folder or not create:
        return folder
    folder = FolderModel(name=safe, owner_id=user_id, parent_id=parent_id)
    db.add(folder)
    db.flush()
    return folder


def _id_v18_context(doc):
    ctx = _ID_V18_BASE_CONTEXT(doc)
    # Image uploads with opaque/hash names can still form a useful visual group
    # when the local caption gives the same clear subject. Avoid generic groups.
    category = str(ctx.get("category") or "General")
    original = str(getattr(doc, "original_name", "") or "")
    extracted = str(getattr(doc, "extracted_text", "") or "").strip()
    file_type = str(getattr(doc, "file_type", "") or "").lower()
    label = str(ctx.get("label") or "").strip()
    label_words = _id_v14_norm(label).split()
    hash_like = _id_v14_is_hash_like(original.rsplit(".", 1)[0])
    generic = _id_v14_norm(label) in {"unclassified images", "unclassified documents", "documents", "document", "general", "file", "image", "images", "to review"}
    if category == "General" and file_type in {"image", "jpg", "jpeg", "png", "webp", "bmp", "tiff"} and hash_like and extracted and len(label_words) >= 2 and not generic:
        ctx["groupable"] = True
        ctx["signals"] = list(ctx.get("signals") or []) + ["local visual/OCR subject context"]
    return ctx


# `_id_v14_group_analyze` resolves this symbol at call time, so the improved image
# context is reused by both single-document routing and the multi-document grouping.
_id_v14_context = _id_v18_context


def _id_v18_create_or_update_route(db, doc, rename_suggestion=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.suggestion import DocumentSuggestion
    repo = SuggestionRepository(db)
    prior = repo.get_existing_for_document(int(doc.id), "route_folder")
    ctx = _id_v18_context(doc)
    destination = _id_v14_target_folder(db, doc, ctx)
    mode = str(destination.get("destination_mode") or "create").lower()

    if mode == "keep_current":
        if prior and prior.status == "pending":
            prior.status = "kept"
            prior.resolved_at = _id_v18_datetime.now(_id_v18_timezone.utc).isoformat()
            prior.resolved_by = int(doc.owner_id)
            db.add(prior)
            db.commit()
        return None

    evidence = {
        "v18_route_folder": True,
        "document_id": int(doc.id),
        "document_name": str(getattr(doc, "display_name", None) or doc.original_name),
        "destination_mode": mode,
        "destination_folder_id": destination.get("destination_folder_id"),
        "destination_parent_id": destination.get("destination_parent_id"),
        "destination_parent_name": destination.get("destination_parent_name"),
        "destination_root_name": destination.get("destination_root_name") or destination.get("destination_parent_name") or destination.get("destination_category") or ctx.get("category") or "General",
        "destination_folder_name": destination.get("destination_folder_name"),
        "destination_folder_path": destination.get("destination_folder_path"),
        "destination_category": destination.get("destination_category") or ctx.get("category") or "General",
        "destination_set_category": bool(destination.get("destination_set_category", ctx.get("set_category"))),
        "filing_signals": list(ctx.get("signals") or [])[:6],
    }
    reason = str(destination.get("destination_reason") or "Suggested from this file's extracted text, OCR, local image description, and category context.")
    path = str(evidence.get("destination_folder_path") or destination.get("destination_folder_name") or "Suggested folder")

    # A resolved Keep/Reject/Apply decision is preserved. Re-evaluation never
    # resurrects the exact same single-file folder decision.
    if prior and prior.status != "pending":
        return None
    if prior and prior.status == "pending":
        prior.current_value = str(getattr(doc, "folder_id", None) or "Unfiled")
        prior.suggested_value = path
        prior.reason = reason
        prior.confidence = 0.92 if ctx.get("strong") else 0.78
        prior.evidence = _id_v18_json.dumps(evidence, ensure_ascii=False)
        db.add(prior)
        db.commit()
        db.refresh(prior)
        return prior
    created = repo.create(
        document_id=int(doc.id), suggestion_type="route_folder",
        current_value="Unfiled", suggested_value=path, reason=reason,
        confidence=0.92 if ctx.get("strong") else 0.78, evidence=evidence,
    )
    return created


def _id_v18_generate(self, db, doc):
    generated = _ID_V18_BASE_GENERATE(self, db, doc) or []
    try:
        from backend.database.repositories.suggestion_repo import SuggestionRepository
        repo = SuggestionRepository(db)
        rename = repo.get_existing_for_document(int(doc.id), "rename")
        route = _id_v18_create_or_update_route(db, doc, rename)
        if route is not None and route.status == "pending" and not any(getattr(s, "id", None) == route.id for s in generated):
            generated.append(route)
    except Exception:
        # Upload must still succeed if the optional route suggestion fails.
        try:
            _ID_V9_LOG.exception("V18 route suggestion generation failed for document %s", getattr(doc, "id", None))
        except Exception:
            pass
    return generated


def _id_v18_parse_path(raw_path, evidence):
    parts = [_id_v18_clean_path_part(p) for p in str(raw_path or "").split("/")]
    parts = [p for p in parts if p]
    if not parts:
        raise ValueError("Destination path cannot be empty.")
    if len(parts) > 3:
        raise ValueError("Use a category and folder path with at most one subfolder level.")
    category = str(evidence.get("destination_category") or evidence.get("category") or parts[0]).strip()
    root_name = parts[0]
    leaf_name = parts[-1]
    if len(parts) == 1:
        # A one-part custom path is interpreted as the category root itself.
        return root_name, None, root_name, category
    return root_name, parts[-2], leaf_name, category


def _id_v18_apply_folder_path(db, user_id, path, evidence):
    from backend.models.folder import FolderModel
    root_name, parent_name, leaf_name, category = _id_v18_parse_path(path, evidence)
    mode = str(evidence.get("destination_mode") or evidence.get("target_mode") or "new").lower()

    if mode == "existing" and not evidence.get("v18_custom_path"):
        folder_id = evidence.get("destination_folder_id") or evidence.get("target_folder_id")
        try:
            folder_id = int(folder_id)
        except (TypeError, ValueError):
            folder_id = None
        folder = db.query(FolderModel).filter(FolderModel.id == folder_id, FolderModel.owner_id == user_id).first() if folder_id else None
        if not folder:
            raise ValueError("The suggested existing folder is no longer available. Re-evaluate the suggestion.")
        return folder, category

    # Reuse existing category/root folders and create only missing path segments.
    root = _id_v18_find_or_create_folder(db, user_id, root_name, None, create=True)
    if not root:
        raise ValueError("Could not create the destination category folder.")
    if parent_name and _id_v14_norm(parent_name) != _id_v14_norm(root_name):
        parent = _id_v18_find_or_create_folder(db, user_id, parent_name, int(root.id), create=True)
        if not parent:
            raise ValueError("Could not create the destination parent folder.")
        leaf_parent_id = int(parent.id)
    else:
        leaf_parent_id = int(root.id)
    if _id_v14_norm(leaf_name) == _id_v14_norm(root.name) and parent_name is None:
        return root, category
    leaf = _id_v18_find_or_create_folder(db, user_id, leaf_name, leaf_parent_id, create=True)
    if not leaf:
        raise ValueError("Could not create the destination subfolder.")
    return leaf, category


def _id_v18_update_folder_doc_category(db, doc, category_name, user_id):
    from backend.models.category import CategoryModel
    known = set(_ID_V12_CATEGORIES)
    if not category_name or category_name not in known:
        return
    doc.category = category_name
    doc.category_source = "user_approved"
    category = db.query(CategoryModel).filter(
        CategoryModel.name == category_name,
        ((CategoryModel.is_system == 1) | (CategoryModel.owner_id == user_id)),
    ).first()
    doc.category_id = int(category.id) if category else None


def _id_v18_resolve_member_routes(db, doc_ids, user_id, group_suggestion_id=None, target_folder=None):
    from backend.models.suggestion import DocumentSuggestion
    rows = db.query(DocumentSuggestion).filter(
        DocumentSuggestion.document_id.in_(list(doc_ids) or [-1]),
        DocumentSuggestion.suggestion_type == "route_folder",
        DocumentSuggestion.status == "pending",
    ).all()
    now = _id_v18_datetime.now(_id_v18_timezone.utc).isoformat()
    for row in rows:
        row.status = "accepted"
        row.resolved_at = now
        row.resolved_by = user_id
        ev = _id_v9_json_value(row.evidence)
        ev["v18_applied_by_group_id"] = group_suggestion_id
        ev["v18_applied_folder_id"] = int(target_folder.id) if target_folder else None
        row.evidence = _id_v18_json.dumps(ev, ensure_ascii=False)
        db.add(row)


def _id_v18_accept(self, db, suggestion_id, user_id, search_service=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel
    from backend.models.suggestion import DocumentSuggestion
    from backend.core.audit_service import AuditService

    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending":
        return None

    if suggestion.suggestion_type == "rename":
        doc = db.query(DocumentModel).filter(
            DocumentModel.id == suggestion.document_id,
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0,
        ).first()
        if not doc:
            return None
        name = _id_v18_re.sub(r"[\\/\x00-\x1f]+", " ", str(suggestion.suggested_value or "")).strip(" .")
        if not name or name in {".", ".."}:
            raise ValueError("Please provide a valid filename.")
        if len(name) > 180:
            raise ValueError("Filename must be 180 characters or fewer.")
        # display_name is the canonical user-visible name used by Library, Details,
        # and Explorer Graph. Keep original_name as upload provenance/audit metadata.
        doc.display_name = name
        suggestion.status = "accepted"
        suggestion.resolved_at = _id_v18_datetime.now(_id_v18_timezone.utc).isoformat()
        suggestion.resolved_by = user_id
        db.add(doc)
        db.add(suggestion)
        # Keep names embedded in pending group evidence synchronized with the visible name.
        pending_groups = db.query(DocumentSuggestion).filter(
            DocumentSuggestion.suggestion_type == "create_folder_group",
            DocumentSuggestion.status == "pending",
        ).all()
        for group in pending_groups:
            ev = _id_v9_json_value(group.evidence)
            ids = ev.get("document_ids") or []
            if int(doc.id) not in {int(x) for x in ids if str(x).isdigit()}:
                continue
            id_to_name = {}
            for raw_id in ids:
                try:
                    d = db.query(DocumentModel).filter(DocumentModel.id == int(raw_id), DocumentModel.owner_id == user_id, DocumentModel.is_deleted == 0).first()
                    if d:
                        id_to_name[int(raw_id)] = d.display_name or d.original_name
                except Exception:
                    continue
            ev["document_names"] = [id_to_name.get(int(x), str(x)) for x in ids]
            group.evidence = _id_v18_json.dumps(ev, ensure_ascii=False)
            db.add(group)
        try:
            AuditService.log(db, action="SUGGESTION_ACCEPT_RENAME", user_id=user_id, resource_type="document", resource_id=doc.uuid, detail={"display_name": name, "original_name_preserved": True})
        except Exception:
            pass
        db.commit()
        db.refresh(suggestion)
        return suggestion

    if suggestion.suggestion_type == "route_folder":
        doc = db.query(DocumentModel).filter(
            DocumentModel.id == suggestion.document_id,
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0,
        ).first()
        if not doc:
            return None
        evidence = _id_v9_json_value(suggestion.evidence)
        path = str(suggestion.suggested_value or evidence.get("destination_folder_path") or "")
        original_path = str(evidence.get("destination_folder_path") or "")
        if path.strip() != original_path.strip():
            evidence["v18_custom_path"] = True
            evidence["destination_mode"] = "create"
            first_part = _id_v18_clean_path_part(path.split("/")[0])
            if first_part in _ID_V12_CATEGORIES:
                evidence["destination_category"] = first_part
                evidence["destination_root_name"] = first_part
        folder, category_name = _id_v18_apply_folder_path(db, user_id, path, evidence)
        doc.folder_id = int(folder.id)
        _id_v18_update_folder_doc_category(db, doc, category_name, user_id)
        suggestion.status = "accepted"
        suggestion.resolved_at = _id_v18_datetime.now(_id_v18_timezone.utc).isoformat()
        suggestion.resolved_by = user_id
        evidence["v18_applied_folder_id"] = int(folder.id)
        evidence["v18_applied_folder_path"] = path
        suggestion.evidence = _id_v18_json.dumps(evidence, ensure_ascii=False)
        db.add(doc)
        db.add(suggestion)
        try:
            AuditService.log(db, action="AI_SMART_FOLDER_APPLIED", user_id=user_id, resource_type="document", resource_id=doc.uuid, detail={"folder_path": path, "folder_id": folder.id, "category": category_name})
        except Exception:
            pass
        db.commit()
        db.refresh(suggestion)
        return suggestion

    if suggestion.suggestion_type == "create_folder_group":
        primary = db.query(DocumentModel).filter(
            DocumentModel.id == suggestion.document_id,
            DocumentModel.owner_id == user_id,
            DocumentModel.is_deleted == 0,
        ).first()
        if not primary:
            return None
        evidence = _id_v9_json_value(suggestion.evidence)
        raw_ids = evidence.get("document_ids") or [primary.id]
        try:
            ids = sorted(set(int(x) for x in raw_ids))
        except (TypeError, ValueError):
            return None
        if len(ids) < 2 or len(ids) != len(raw_ids):
            return None
        docs = db.query(DocumentModel).filter(
            DocumentModel.id.in_(ids), DocumentModel.owner_id == user_id, DocumentModel.is_deleted == 0
        ).all()
        if {int(d.id) for d in docs} != set(ids):
            return None
        path = str(suggestion.suggested_value or evidence.get("target_folder_path") or "")
        original_group_path = str(evidence.get("target_folder_path") or "")
        custom_group_path = path.strip() != original_group_path.strip()
        custom_root = _id_v18_clean_path_part(path.split("/")[0]) if custom_group_path else ""
        group_category = (custom_root if custom_root in _ID_V12_CATEGORIES else (evidence.get("suggested_category") or evidence.get("category") or "General"))
        target_evidence = {
            **evidence,
            "v18_custom_path": custom_group_path,
            "destination_mode": ("create" if custom_group_path else (evidence.get("target_mode") or "new")),
            "destination_folder_id": evidence.get("target_folder_id"),
            "destination_parent_id": evidence.get("target_parent_id"),
            "destination_root_name": (custom_root if custom_group_path else (evidence.get("destination_root_name") or evidence.get("category") or "General")),
            "destination_folder_name": path.split("/")[-1].strip() if custom_group_path else (evidence.get("suggested_folder_name") or path.split("/")[-1]),
            "destination_category": group_category,
        }
        folder, category_name = _id_v18_apply_folder_path(db, user_id, path, target_evidence)
        for doc in docs:
            doc.folder_id = int(folder.id)
            _id_v18_update_folder_doc_category(db, doc, category_name, user_id)
            db.add(doc)
        suggestion.status = "accepted"
        suggestion.resolved_at = _id_v18_datetime.now(_id_v18_timezone.utc).isoformat()
        suggestion.resolved_by = user_id
        evidence["v18_applied_folder_id"] = int(folder.id)
        evidence["v18_applied_folder_path"] = path
        suggestion.evidence = _id_v18_json.dumps(evidence, ensure_ascii=False)
        db.add(suggestion)
        _id_v18_resolve_member_routes(db, ids, user_id, group_suggestion_id=int(suggestion.id), target_folder=folder)
        try:
            AuditService.log(db, action="AI_FOLDER_GROUP_APPLIED", user_id=user_id, resource_type="folder", resource_id=str(folder.id), detail={"folder_path": path, "document_ids": ids})
        except Exception:
            pass
        db.commit()
        db.refresh(suggestion)
        return suggestion

    return _ID_V18_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)


def _id_v18_group_analyze(self, db, user_id):
    # V14 analyzer now sees General image documents when the local caption supplies a usable subject.
    return _ID_V18_BASE_GROUP_ANALYZE(self, db, user_id) or []


OrganizationService.generate_suggestions_for_document = _id_v18_generate
OrganizationService.accept_suggestion = _id_v18_accept
OrganizationService.analyze_library_folder_groups = _id_v18_group_analyze
# === End IntelliDocs Smart Filing Lifecycle V18 ===


# === INTELLIDOCS_RECIPIENT_PRIVATE_ORG_V1 ===
_ID_V20_CANONICAL_ACCEPT = OrganizationService.accept_suggestion

def _id_v20_personal_accept(self, db, suggestion_id, user_id, search_service=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.user_document_preference import UserDocumentPreference
    from backend.models.folder import FolderModel
    from backend.core.permission_service import PermissionService
    from backend.models.user import User
    from datetime import datetime, timezone
    import re

    repo = SuggestionRepository(db)
    suggestion = repo.get_by_id(suggestion_id)
    if not suggestion or suggestion.status != "pending":
        return None
    scoped_user_id = getattr(suggestion, "created_for_user_id", None)
    if scoped_user_id is not None and int(scoped_user_id) != int(user_id):
        return None
    if scoped_user_id is None:
        return _ID_V20_CANONICAL_ACCEPT(self, db, suggestion_id, user_id, search_service)

    doc = db.query(DocumentModel).filter(
        DocumentModel.id == suggestion.document_id, DocumentModel.is_deleted == 0
    ).first()
    actor = db.query(User).filter(User.id == user_id).first()
    if not doc or doc.owner_id == user_id or not actor or not PermissionService.can_read(db, actor, doc):
        return None
    if suggestion.suggestion_type not in {"rename", "route_folder", "categorize"}:
        return None

    pref = db.query(UserDocumentPreference).filter(
        UserDocumentPreference.user_id == user_id,
        UserDocumentPreference.document_id == doc.id,
    ).first()
    if not pref:
        pref = UserDocumentPreference(user_id=user_id, document_id=doc.id)
        db.add(pref)
        db.flush()

    if suggestion.suggestion_type == "rename":
        value = re.sub(r"[\\/\x00-\x1f]+", " ", str(suggestion.suggested_value or "")).strip(" .")
        if not value or value in {".", ".."} or len(value) > 180:
            return None
        pref.display_name = value
    elif suggestion.suggestion_type == "categorize":
        value = str(suggestion.suggested_value or "").strip()[:80]
        if not value:
            return None
        pref.category = value
    elif suggestion.suggestion_type == "route_folder":
        evidence = _id_v9_json_value(suggestion.evidence)
        path = str(suggestion.suggested_value or evidence.get("destination_folder_path") or "").strip()
        pieces = [_id_v18_clean_path_part(x) for x in path.split("/")]
        pieces = [x for x in pieces if x]
        if not pieces or len(pieces) > 3:
            return None
        parent = None
        folder = None
        for piece in pieces:
            rows = db.query(FolderModel).filter(
                FolderModel.owner_id == user_id,
                FolderModel.parent_id.is_(None) if parent is None else FolderModel.parent_id == parent.id,
            ).all()
            folder = next((f for f in rows if _id_v14_norm(f.name) == _id_v14_norm(piece)), None)
            if not folder:
                folder = FolderModel(name=piece, owner_id=user_id, parent_id=parent.id if parent else None)
                db.add(folder)
                db.flush()
            parent = folder
        pref.folder_id = folder.id
        category_value = str(evidence.get("destination_category") or "").strip()
        if category_value and bool(evidence.get("destination_set_category")):
            pref.category = category_value[:80]

    now = datetime.now(timezone.utc).isoformat()
    suggestion.status = "accepted"
    suggestion.resolved_at = now
    suggestion.resolved_by = user_id
    pref.updated_at = now
    db.add(pref)
    db.add(suggestion)
    db.commit()
    db.refresh(suggestion)
    return suggestion

OrganizationService.accept_suggestion = _id_v20_personal_accept
# === END INTELLIDOCS_RECIPIENT_PRIVATE_ORG_V1 ===


# === INTELLIDOCS_RECIPIENT_PERSONAL_GROUP_ANALYSIS_V1 ===
# The existing group analyzer is intentionally preserved for a normal owner library.
# For a recipient, create a separate, user-scoped group suggestion over activated,
# unlocked documents. Accepting it creates/uses recipient-owned folders and changes
# only the recipient's preferences for shared files.
_ID_V21_BASE_GROUP_ANALYZE = OrganizationService.analyze_library_folder_groups
_ID_V21_BASE_ACCEPT = OrganizationService.accept_suggestion

def _id_v21_recipient_group_analyze(self, db, user_id, lock_token=None, lock_tokens=None):
    scope_user_id = db.info.get("suggestion_scope_user_id")
    if scope_user_id is None:
        return _ID_V21_BASE_GROUP_ANALYZE(self, db, user_id) or []
    if int(scope_user_id) != int(user_id):
        return []

    from backend.core.permission_service import PermissionService
    from backend.models.document import DocumentModel
    from backend.models.document_relation import DocumentRelation
    from backend.models.folder import FolderModel
    from backend.models.suggestion import DocumentSuggestion
    from backend.models.user import User
    from backend.database.repositories.document_repo import DocumentRepository
    import json as _id_v21_json

    actor = db.query(User).filter(User.id == int(user_id)).first()
    if not actor:
        return []
    accessible_ids = set(PermissionService.list_accessible_document_ids(db, int(user_id)))
    if not accessible_ids:
        return []
    docs = db.query(DocumentModel).filter(
        DocumentModel.id.in_(accessible_ids), DocumentModel.is_deleted == 0
    ).order_by(DocumentModel.id.asc()).all()
    # Group analysis never reads a shared document that remains Access-Locked.
    # A caller-provided token is document-specific; it only unlocks a row if it
    # actually validates for that row, and is never accepted as a bypass.
    docs = [
        d for d in docs
        if PermissionService.check_access_lock(
            db, actor, d,
            PermissionService.resolve_access_lock_token(
                db, actor, d, lock_tokens=lock_tokens,
                fallback_token=lock_token,
            ),
        )
    ]

    contexts = {}
    clusters = {}
    for doc in docs:
        ctx = _id_v14_context(doc)
        contexts[int(doc.id)] = ctx
        category = str(ctx.get("category") or "General")
        label = str(ctx.get("label") or "").strip()
        if not label or not ctx.get("groupable"):
            continue
        key = (_id_v14_norm(category), _id_v14_norm(label))
        clusters.setdefault(key, {"category": category, "label": label, "docs": []})["docs"].append(doc)

    # Only recipient-specific group suggestions that contain at least one shared
    # document are new here; normal owner-only groups are handled by the original analyzer.
    existing_rows = db.query(DocumentSuggestion).filter(
        DocumentSuggestion.created_for_user_id == int(user_id),
        DocumentSuggestion.suggestion_type == "create_folder_group",
    ).order_by(DocumentSuggestion.created_at.desc()).all()
    generated = []
    for (cat_norm, label_norm), cluster in clusters.items():
        members = sorted(cluster["docs"], key=lambda d: int(d.id))
        if len(members) < 2 or not any(int(d.owner_id) != int(user_id) for d in members):
            continue
        category, label = cluster["category"], cluster["label"]
        ids_signature = sorted(int(d.id) for d in members)
        key = f"v21-recipient:{int(user_id)}:{cat_norm}:{label_norm}"
        plan = _id_v14_folder_plan(db, int(user_id), category, label)
        target_folder_id = plan.get("target_folder_id")
        actionable = False
        for member in members:
            if int(member.owner_id) == int(user_id):
                current_folder_id = getattr(member, "folder_id", None)
            else:
                from backend.core.document_view_service import get_preference
                pref = get_preference(db, int(user_id), int(member.id))
                current_folder_id = pref.folder_id if pref else None
            if target_folder_id is None or int(current_folder_id or 0) != int(target_folder_id or 0):
                actionable = True
                break
        matching = []
        for prior in existing_rows:
            ev = _id_v9_json_value(prior.evidence)
            if ev.get("v21_recipient_group_key") == key:
                matching.append((prior, ev))
        exact_resolved = any(
            prior.status != "pending"
            and sorted(int(x) for x in (ev.get("document_ids") or [])) == ids_signature
            for prior, ev in matching
        )
        pending = [(prior, ev) for prior, ev in matching if prior.status == "pending"]
        if not actionable or exact_resolved:
            for prior, ev in pending:
                prior.status = "rejected" if exact_resolved else "kept"
                prior.resolved_at = _id_v14_datetime.now(_id_v14_timezone.utc).isoformat()
                prior.resolved_by = int(user_id)
                ev["v21_auto_closed_reason"] = "Group membership was already resolved or is already filed."
                prior.evidence = _id_v21_json.dumps(ev, ensure_ascii=False)
                db.add(prior)
            continue

        names = [str(getattr(d, "display_name", None) or d.original_name) for d in members]
        evidence = {
            "v21_recipient_group_key": key,
            "v21_recipient_personal": True,
            # Current Suggestions renderers only show evidence-backed strong groups.
            "v14_strong_group": True,
            "v14_group_key": key,
            "v14_membership_ids": ids_signature,
            "document_ids": ids_signature,
            "document_names": names,
            "category": category,
            "suggested_category": category,
            "suggested_folder_name": label,
            "target_mode": plan.get("target_mode"),
            "target_folder_id": plan.get("target_folder_id"),
            "target_parent_id": plan.get("target_parent_id"),
            "target_folder_path": plan.get("target_folder_path") or str(plan.get("target_folder_name") or label),
            "destination_root_name": plan.get("destination_root_name"),
            "shared_signals": sorted({str(sig) for d in members for sig in contexts[int(d.id)].get("signals", [])})[:10],
            "status_label": "PENDING",
        }
        reason = f"{len(members)} accessible documents share the {category} context '{label}'. This recommendation changes your own folder and view for shared documents; it does not change the sender's original file."
        if pending:
            pending.sort(key=lambda item: str(getattr(item[0], "created_at", "")), reverse=True)
            row, _old_ev = pending[0]
            for duplicate, duplicate_ev in pending[1:]:
                duplicate.status = "rejected"
                duplicate.resolved_at = _id_v14_datetime.now(_id_v14_timezone.utc).isoformat()
                duplicate.resolved_by = int(user_id)
                duplicate_ev["v21_superseded_by"] = int(row.id)
                duplicate.evidence = _id_v21_json.dumps(duplicate_ev, ensure_ascii=False)
                db.add(duplicate)
            row.document_id = int(members[0].id)
            row.current_value = "Unorganized"
            row.suggested_value = str(evidence["target_folder_path"])
            row.reason = reason
            row.confidence = 0.92
            row.evidence = _id_v21_json.dumps(evidence, ensure_ascii=False)
            db.add(row)
            generated.append(row)
        else:
            row = DocumentSuggestion(
                document_id=int(members[0].id),
                created_for_user_id=int(user_id),
                suggestion_type="create_folder_group",
                current_value="Unorganized",
                suggested_value=str(evidence["target_folder_path"]),
                reason=reason,
                confidence=0.92,
                evidence=_id_v21_json.dumps(evidence, ensure_ascii=False),
                status="pending",
            )
            db.add(row)
            db.flush()
            generated.append(row)
    db.commit()
    return generated


def _id_v21_personal_group_accept(self, db, suggestion_id, user_id, search_service=None, lock_tokens=None):
    from backend.database.repositories.suggestion_repo import SuggestionRepository
    from backend.models.document import DocumentModel
    from backend.models.folder import FolderModel
    from backend.models.suggestion import DocumentSuggestion
    from backend.models.user_document_preference import UserDocumentPreference
    from backend.models.user import User
    from backend.core.permission_service import PermissionService
    import json as _id_v21_json
    from datetime import datetime as _id_v21_datetime, timezone as _id_v21_timezone

    row = SuggestionRepository(db).get_by_id(suggestion_id)
    if not row or row.status != "pending":
        return None
    scoped_user_id = getattr(row, "created_for_user_id", None)
    if scoped_user_id is None or int(scoped_user_id) != int(user_id) or row.suggestion_type != "create_folder_group":
        return _ID_V21_BASE_ACCEPT(self, db, suggestion_id, user_id, search_service)

    ev = _id_v9_json_value(row.evidence)
    if not ev.get("v21_recipient_personal"):
        return None
    try:
        ids = sorted({int(x) for x in (ev.get("document_ids") or [])})
    except (TypeError, ValueError):
        return None
    if len(ids) < 2:
        return None
    accessible = set(PermissionService.list_accessible_document_ids(db, int(user_id)))
    if not set(ids).issubset(accessible):
        return None
    actor = db.query(User).filter(User.id == int(user_id)).first()
    docs = db.query(DocumentModel).filter(
        DocumentModel.id.in_(ids), DocumentModel.is_deleted == 0
    ).all()
    if len(docs) != len(ids) or not actor:
        return None
    by_id = {int(d.id): d for d in docs}
    for doc in docs:
        if not PermissionService.can_read(db, actor, doc):
            return None
        doc_token = PermissionService.resolve_access_lock_token(
            db, actor, doc, lock_tokens=lock_tokens,
        )
        if not PermissionService.check_access_lock(db, actor, doc, doc_token):
            return None

    path = str(ev.get("target_folder_path") or row.suggested_value or "").strip()
    pieces = [_id_v18_clean_path_part(piece) for piece in path.split("/")]
    pieces = [piece for piece in pieces if piece]
    if not pieces or len(pieces) > 3:
        return None
    parent = None
    folder = None
    for piece in pieces:
        rows = db.query(FolderModel).filter(
            FolderModel.owner_id == int(user_id),
            FolderModel.parent_id.is_(None) if parent is None else FolderModel.parent_id == int(parent.id),
        ).all()
        folder = next((f for f in rows if _id_v14_norm(f.name) == _id_v14_norm(piece)), None)
        if not folder:
            folder = FolderModel(name=piece, owner_id=int(user_id), parent_id=int(parent.id) if parent else None)
            db.add(folder)
            db.flush()
        parent = folder

    category = str(ev.get("suggested_category") or ev.get("category") or "").strip()[:80]
    for doc in docs:
        if int(doc.owner_id) == int(user_id):
            doc.folder_id = int(folder.id)
            if category and (not doc.category or doc.category == "General"):
                doc.category = category
            db.add(doc)
        else:
            pref = db.query(UserDocumentPreference).filter(
                UserDocumentPreference.user_id == int(user_id),
                UserDocumentPreference.document_id == int(doc.id),
            ).first()
            if not pref:
                pref = UserDocumentPreference(user_id=int(user_id), document_id=int(doc.id))
                db.add(pref)
                db.flush()
            pref.folder_id = int(folder.id)
            if category:
                pref.category = category
            pref.updated_at = _id_v21_datetime.now(_id_v21_timezone.utc).isoformat()
            db.add(pref)

    row.status = "accepted"
    row.resolved_at = _id_v21_datetime.now(_id_v21_timezone.utc).isoformat()
    row.resolved_by = int(user_id)
    ev["v21_applied_folder_id"] = int(folder.id)
    row.evidence = _id_v21_json.dumps(ev, ensure_ascii=False)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


OrganizationService.analyze_library_folder_groups = _id_v21_recipient_group_analyze
OrganizationService.accept_suggestion = _id_v21_personal_group_accept
# === END INTELLIDOCS_RECIPIENT_PERSONAL_GROUP_ANALYSIS_V1 ===


# === INTELLIDOCS_RECIPIENT_CERTIFICATE_GROUP_DESTINATION_V2 ===
# Fix recipient-side filing: never use the owner's folder assignment as the
# recipient's destination. Also normalize strong certificate signals into one
# meaningful category cluster while preserving each document's own smart name.
import re as _id_v22_re

_ID_V22_BASE_CONTEXT = _id_v18_context
_ID_V22_BASE_TARGET_FOLDER = _id_v14_target_folder
_ID_V22_BASE_FOLDER_PLAN = _id_v14_folder_plan
_ID_V22_CERT_PATTERN = _id_v22_re.compile(r"\b(?:certificate|certificates|certification|certifications|certified|credential|credentials|diploma|diplomas)\b", _id_v22_re.I)

def _id_v22_context(doc):
    ctx = dict(_ID_V22_BASE_CONTEXT(doc) or {})
    original = str(getattr(doc, "original_name", None) or "")
    display = str(getattr(doc, "display_name", None) or "")
    extracted = str(getattr(doc, "extracted_text", None) or "")
    category = str(getattr(doc, "category", None) or ctx.get("category") or "").strip()
    normalized_blob = f" {original} {display} {extracted} {category} ".replace("_", " ").replace("-", " ")
    filename_signal = bool(_ID_V22_CERT_PATTERN.search(f" {original} {display} ".replace("_", " ").replace("-", " ")))
    category_signal = _id_v14_norm(category) in {"certificate", "certification", "credential", "diploma"}
    text_signal = bool(_ID_V22_CERT_PATTERN.search(extracted)) and bool(_id_v22_re.search(
        r"\b(certificate of|this is to certify|certification|credential|awarded to|successfully completed|has completed)\b",
        extracted, _id_v22_re.I
    ))
    if filename_signal or category_signal or text_signal:
        ctx["category"] = "Certificate"
        ctx["category_folder_name"] = "Certificates"
        ctx["label"] = "Certificates"
        ctx["groupable"] = True
        ctx["signals"] = list(dict.fromkeys(list(ctx.get("signals") or []) + ["certificate/certification document type"]))[:8]
        # Keep the classifier's strong flag unchanged; grouping is justified by
        # an explicit document-type signal rather than an inflated confidence.
    return ctx


def _id_v22_folder_plan(db, user_id, category, label):
    # Avoid producing the redundant path "Certificate / Certificates". A
    # certificate destination is the recipient-owned "Certificates" folder.
    if _id_v14_norm(category) == "certificate" and _id_v14_norm(label) == "certificates":
        from backend.models.folder import FolderModel
        roots = db.query(FolderModel).filter(
            FolderModel.owner_id == int(user_id), FolderModel.parent_id.is_(None)
        ).all()
        found = next((f for f in roots if _id_v14_norm(f.name) == "certificates"), None)
        if found:
            folders = _id_v10_folder_maps(db, int(user_id))
            path = _id_v10_folder_path(found.id, folders) or found.name
            return {
                "target_mode": "existing", "target_folder_id": int(found.id),
                "target_parent_id": None, "target_folder_path": path,
                "destination_root_name": str(found.name),
            }
        return {
            "target_mode": "new", "target_folder_id": None,
            "target_parent_id": None, "target_folder_path": "Certificates",
            "destination_root_name": "Certificates",
        }
    return _ID_V22_BASE_FOLDER_PLAN(db, user_id, category, label)


def _id_v22_target_folder(db, doc, ctx=None):
    scope_user_id = db.info.get("suggestion_scope_user_id")
    # Owner-generated recommendations retain the original behavior.
    if scope_user_id is None or int(scope_user_id) == int(doc.owner_id):
        return _ID_V22_BASE_TARGET_FOLDER(db, doc, ctx)

    from backend.models.folder import FolderModel
    from backend.core.document_view_service import get_preference
    recipient_id = int(scope_user_id)
    ctx = dict(ctx or _id_v22_context(doc))

    # Only a recipient-owned preference can mean "keep current" for the recipient.
    pref = get_preference(db, recipient_id, int(doc.id))
    folders = _id_v10_folder_maps(db, recipient_id)
    pref_folder_id = getattr(pref, "folder_id", None) if pref else None
    if pref_folder_id and int(pref_folder_id) in folders:
        folder = folders[int(pref_folder_id)]
        path = _id_v10_folder_path(folder.id, folders) or str(folder.name)
        return {
            "destination_mode": "keep_current", "destination_folder_id": int(folder.id),
            "destination_parent_id": folder.parent_id,
            "destination_parent_name": None, "destination_folder_name": str(folder.name),
            "destination_folder_path": path, "destination_category": ctx.get("category") or "General",
            "destination_set_category": bool(ctx.get("set_category")),
            "destination_reason": "This document is already filed in your personal view; approval keeps your current destination.",
        }

    category = str(ctx.get("category") or "General").strip() or "General"
    label = str(ctx.get("label") or "Documents").strip() or "Documents"
    plan = _id_v22_folder_plan(db, recipient_id, category, label)
    mode = "existing" if plan.get("target_mode") == "existing" and plan.get("target_folder_id") else "create"
    folder_id = plan.get("target_folder_id") if mode == "existing" else None
    folder = db.query(FolderModel).filter(
        FolderModel.id == int(folder_id), FolderModel.owner_id == recipient_id
    ).first() if folder_id else None
    folder_path = str(plan.get("target_folder_path") or label)
    parent_id = plan.get("target_parent_id")
    parent = db.query(FolderModel).filter(
        FolderModel.id == int(parent_id), FolderModel.owner_id == recipient_id
    ).first() if parent_id else None
    return {
        "destination_mode": mode,
        "destination_folder_id": int(folder.id) if folder else None,
        "destination_parent_id": int(parent.id) if parent else (int(parent_id) if parent_id else None),
        "destination_parent_name": str(parent.name) if parent else None,
        "destination_folder_name": str(folder.name) if folder else label,
        "destination_folder_path": folder_path,
        "destination_category": category,
        "destination_set_category": bool(ctx.get("set_category")),
        "destination_root_name": plan.get("destination_root_name") or category,
        "destination_reason": (
            "A matching folder exists in your own filing space." if mode == "existing"
            else "Suggested from the received document's content/type and your personal filing space. The folder is created only after your approval."
        ),
    }


# Retain existing service entry points: their call sites resolve these names at runtime.
_id_v18_context = _id_v22_context
_id_v14_context = _id_v22_context
_id_v14_folder_plan = _id_v22_folder_plan
_id_v14_target_folder = _id_v22_target_folder
# === END INTELLIDOCS_RECIPIENT_CERTIFICATE_GROUP_DESTINATION_V2 ===
