import uuid
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, List
from sqlalchemy.orm import Session
from backend.config import settings
from backend.security.file_validator import FileValidator, ValidationResult
from backend.security.path_guard import PathGuard
from backend.algorithms.hashing import sha256_bytes
from backend.document_processing.base_processor import DocumentProcessor
from backend.database.repositories.document_repo import DocumentRepository
from backend.core.audit_service import AuditService
from backend.core.sensitivity_service import SensitivityService
from backend.core.categorization_service import CategorizationService
from backend.core.duplicate_service import DuplicateService
from backend.core.search_service import SearchService
from backend.core.organization_service import OrganizationService
from backend.core.notification_service import NotificationService
from backend.ai.embedding_engine import EmbeddingEngine
from backend.ai.vector_store import VectorStore

class DocumentService:
    def __init__(
        self,
        search_service: SearchService,
        duplicate_service: DuplicateService,
        embedding_engine: EmbeddingEngine,
        vector_store: VectorStore
    ):
        self.path_guard = PathGuard()
        self.search_service = search_service
        self.duplicate_service = duplicate_service
        self.embedding_engine = embedding_engine
        self.vector_store = vector_store
        self.sensitivity_service = SensitivityService()
        self.categorization_service = CategorizationService(embedding_engine=self.embedding_engine)
        self.organization_service = OrganizationService(embedding_engine=self.embedding_engine)

    def process_and_store_upload(
        self,
        db: Session,
        filename: str,
        content_type: str,
        file_bytes: bytes,
        owner_id: int,
        parent_version_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[Any, Dict[str, Any]]:
        # 1. State: Request validation
        validation: ValidationResult = FileValidator.validate_upload(filename, content_type, file_bytes)
        if not validation.valid:
            AuditService.log(
                db, action="DOCUMENT_UPLOAD_FAILED", user_id=owner_id,
                ip_address=ip_address, user_agent=user_agent,
                detail={"filename": filename, "error": validation.error}, success=0
            )
            raise ValueError(validation.error)

        doc_repo = DocumentRepository(db)

        # Handle versioning fields
        version_group_id = str(uuid.uuid4())
        version_number = 1
        if parent_version_id:
            parent_doc = doc_repo.get_by_id(parent_version_id)
            if parent_doc and parent_doc.owner_id == owner_id:
                version_group_id = parent_doc.version_group_id or str(uuid.uuid4())
                version_number = (parent_doc.version_number or 1) + 1

        # 2. Generate safe internal storage filename (UUID + safe ext)
        doc_uuid = str(uuid.uuid4())
        ext = FileValidator.ALLOWED_MIME_TYPES[validation.mime_type]
        stored_name = f"{doc_uuid}.{ext}"

        # 3. Path traversal protection: store outside frontend directory
        dest_path = self.path_guard.safe_upload_path(stored_name)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        with open(dest_path, "wb") as f:
            f.write(file_bytes)

        # 4. Fingerprinting: SHA-256
        sha256_hash = sha256_bytes(file_bytes)

        # 5. Extract text & metadata using OOP Processor Factory
        processor = DocumentProcessor.for_mime_type(validation.mime_type)
        processed = processor.extract(dest_path)

        # Generate thumbnail
        thumb_name = f"{doc_uuid}.png"
        thumb_path = self.path_guard.safe_thumbnail_path(thumb_name)
        thumb_path.parent.mkdir(parents=True, exist_ok=True)
        processor.generate_thumbnail(dest_path, thumb_path)

        # 6. Categorization, Sensitivity, Summary & Key Topics analysis
        sensitivity, pii_types = self.sensitivity_service.analyze(processed.text)
        category, confidence, cat_source, cat_evidence = self.categorization_service.categorize_multi_signal(
            text=processed.text or "",
            filename=filename,
            file_type=validation.file_type,
            pii_types=pii_types,
            ocr_confidence=processed.ocr_confidence
        )

        from backend.ai.summarizer import Summarizer
        import json
        summarizer = Summarizer()
        doc_summary = summarizer.summarize_document(processed.text, filename=filename)
        doc_topics = summarizer.extract_key_topics(processed.text, filename, category)

        # 7. Create database record
        doc_record = doc_repo.create({
            "uuid": doc_uuid,
            "original_name": filename,
            "display_name": filename,
            "stored_name": stored_name,
            "file_path": f"uploads/{stored_name}",
            "file_type": validation.file_type,
            "mime_type": validation.mime_type,
            "size_bytes": len(file_bytes),
            "sha256_hash": sha256_hash,
            "page_count": processed.page_count,
            "word_count": processed.word_count,
            "extracted_text": processed.text,
            "summary": doc_summary,
            "key_topics": json.dumps(doc_topics),
            "language": processed.language,
            "category": "General",
            "category_source": "system_default",
            "sensitivity": sensitivity,
            "has_ocr": 1 if processed.has_ocr else 0,
            "ocr_confidence": processed.ocr_confidence,
            "has_embedded_js": 1 if processed.has_embedded_js else 0,
            "perceptual_hash": getattr(processed, "perceptual_hash", None),
            "version_group_id": version_group_id,
            "version_number": version_number,
            "parent_version_id": parent_version_id,
            "owner_id": owner_id,
            "processing_status": "analyzing"
        })

        # === IntelliDocs upload -> library grouping trigger V8 ===
        # Persist the already-computed AI category so library organization can
        # reason from the actual document class instead of the placeholder General.
        try:
            if category and str(category).strip().lower() != "general":
                doc_record.category = category
                doc_record.category_source = cat_source
                from backend.database.repositories.category_repo import CategoryRepository
                _cat_repo_v7 = CategoryRepository(db)
                _cat_obj_v7 = _cat_repo_v7.get_by_name(category, owner_id=owner_id)
                if _cat_obj_v7:
                    doc_record.category_id = _cat_obj_v7.id
                db.commit()
                db.refresh(doc_record)
        except Exception:
            pass

        # Create version history record if revision
        if parent_version_id:
            from backend.models.document_relation import DocumentVersion
            parent_ver = db.query(DocumentVersion).filter(DocumentVersion.document_id == parent_version_id).first()
            parent_ver_id = parent_ver.id if parent_ver else None
            ver_rec = DocumentVersion(
                document_id=doc_record.id,
                version_number=version_number,
                parent_id=parent_ver_id,
                change_summary=f"Uploaded new revision v{version_number} of {filename}",
                created_by=owner_id
            )
            db.add(ver_rec)
            db.commit()

        # 8. 5-Level Multi-Evidence Duplicate Intelligence
        eb_list = self.duplicate_service.analyze_all_candidates(db, doc_record, owner_id)
        has_exact = any(eb.relation_type == "exact_duplicate" for eb in eb_list)

        # 9. MinHash / LSH near-duplicate indexing
        if processed.text:
            self.duplicate_service.lsh_index.add(doc_record.id, processed.text)

        # 10. Hybrid Search Inverted Index & Trie indexing
        if processed.text:
            self.search_service.index_document(doc_record.id, processed.text)

        # 11. SentenceTransformers Dense Vector Store Embedding
        if self.embedding_engine.is_available() and processed.text:
            vector = self.embedding_engine.encode(processed.text)
            self.vector_store.add(doc_record.id, vector)
            doc_repo.update(doc_record.id, {"embedding_stored": 1})

        # 12. Smart Organization Suggestions
        doc_repo.update(doc_record.id, {"processing_status": "suggesting"})
        suggestions = self.organization_service.generate_suggestions_for_document(db, doc_record)

        # V8: evaluate the user's existing library for contextual grouping.
        # This only creates approval suggestions; it never moves/creates folders.
        try:
            self.organization_service.analyze_library_folder_groups(db, owner_id)
        except Exception:
            # Grouping is an enhancement and must never fail a successful upload.
            pass

        # Mark done
        doc_repo.update(doc_record.id, {"processing_status": "done"})

        # 13. Audit & Notifications
        AuditService.log(
            db, action="DOCUMENT_UPLOAD", user_id=owner_id,
            resource_type="document", resource_id=doc_uuid,
            ip_address=ip_address, user_agent=user_agent,
            detail={
                "original_name": filename,
                "file_type": validation.file_type,
                "size_bytes": len(file_bytes),
                "sha256": sha256_hash,
                "category": category,
                "suggested_category": category,
                "category_source": cat_source,
                "category_confidence": confidence,
                "category_evidence": cat_evidence,
                "sensitivity": sensitivity,
                "candidate_relations_count": len(eb_list),
                "version_number": version_number
            }
        )

        NotificationService.notify(
            db,
            user_id=owner_id,
            event_type="PROCESSING_COMPLETE",
            title="Processing Complete",
            message=f"Document '{filename}' successfully processed and analyzed.",
            document_id=doc_record.id
        )

        if has_exact or len(eb_list) > 0:
            NotificationService.notify(
                db,
                user_id=owner_id,
                event_type="DUPLICATE_DETECTED",
                title="Duplicate / Similar Document Detected",
                message=f"Found {len(eb_list)} potential duplicate or related document(s) for '{filename}'",
                document_id=doc_record.id
            )

        dup_summary = {
            "has_exact_duplicate": has_exact,
            "candidate_count": len(eb_list),
            "candidates": [
                {
                    "document_uuid": eb.doc_b_uuid,
                    "original_name": eb.doc_b_name,
                    "relation_type": eb.relation_type,
                    "confidence": eb.confidence,
                    "scores": eb.scores,
                    "detection_methods": eb.detection_methods,
                    "supporting_evidence": eb.supporting_evidence
                } for eb in eb_list
            ]
        }

        return doc_record, dup_summary
