import json
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.folder import FolderModel
from backend.models.category import CategoryModel
from backend.models.tag import Tag
from backend.models.document_relation import DocumentRelation, DocumentVersion
from backend.models.audit_log import AuditLog
from backend.database.repositories.document_repo import DocumentRepository

class ExplorerService:
    """
    Power BI-Style Relationship Graph and Chronological Audit History Explorer Service.
    Populates node-edge graphs strictly using real persisted database records.
    Enforces authenticated ownership isolation.
    """

    @staticmethod
    def build_user_graph(db: Session, current_user: User, lock_token: Optional[str] = None) -> Dict[str, Any]:
        nodes = []
        edges = []
        seen_node_ids = set()

        def add_node(node_id: str, label: str, node_type: str, details: Dict[str, Any]):
            if node_id not in seen_node_ids:
                seen_node_ids.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "type": node_type,
                    "details": details
                })

        def add_edge(source: str, target: str, relation: str, score: float = 1.0, extra: Optional[Dict[str, Any]] = None):
            edges.append({
                "source": source,
                "target": target,
                "relation": relation,
                "score": score,
                "extra": extra or {}
            })

        # 1. User Node
        user_node_id = f"user_{current_user.id}"
        add_node(user_node_id, current_user.username, "User", {"email": current_user.email, "role": current_user.role})

        # 2. Document Nodes (owned and shared)
        from backend.core.permission_service import PermissionService
        accessible_ids = PermissionService.list_accessible_document_ids(db, current_user.id)
        access_docs = db.query(DocumentModel).filter(DocumentModel.id.in_(accessible_ids or [-1]), DocumentModel.is_deleted == 0).all()
        accessible_ids = {d.id for d in access_docs if PermissionService.check_access_lock(db, current_user, d, lock_token)}

        user_docs = db.query(DocumentModel).filter(
            DocumentModel.id.in_(accessible_ids) if accessible_ids else DocumentModel.owner_id == current_user.id,
            DocumentModel.is_deleted == 0
        ).all()

        doc_dict = {d.id: d for d in user_docs}
        from backend.core.document_view_service import effective_fields

        for doc in user_docs:
            view_fields = effective_fields(db, doc, current_user.id)
            doc_node_id = f"doc_{doc.id}"
            display_title = view_fields.get("display_name") or doc.original_name
            add_node(doc_node_id, display_title, "Document", {
                "uuid": doc.uuid,
                "file_type": doc.file_type,
                "category": view_fields.get("category"),
                "sensitivity": doc.sensitivity,
                "size_bytes": doc.size_bytes
            })
            # Edge: User owns or has access to Document
            relation_label = "owns" if doc.owner_id == current_user.id else "shared_access"
            add_edge(user_node_id, doc_node_id, relation_label)

            # Folder Node & Edge
            view_folder_id = view_fields.get("folder_id")
            if view_folder_id:
                folder = db.query(FolderModel).filter(FolderModel.id == view_folder_id, FolderModel.owner_id == current_user.id).first()
                if folder:
                    folder_node_id = f"folder_{folder.id}"
                    add_node(folder_node_id, folder.name, "Folder", {"id": folder.id})
                    add_edge(doc_node_id, folder_node_id, "belongs_to")

            # Category Node & Edge
            effective_category = view_fields.get("category")
            if effective_category:
                cat_node_id = f"cat_{effective_category.lower().replace(' ', '_')}"
                add_node(cat_node_id, effective_category, "Category", {"name": effective_category})
                add_edge(doc_node_id, cat_node_id, "categorized_as")

            # Tag Nodes & Edges
            for tag in view_fields.get("tags", []):
                tag_node_id = f"tag_{tag.id}"
                add_node(tag_node_id, tag.name, "Tag", {"color": tag.color})
                add_edge(doc_node_id, tag_node_id, "has_tag")

            # Version Grouping Edge
            if doc.parent_version_id and doc.parent_version_id in doc_dict:
                parent_node_id = f"doc_{doc.parent_version_id}"
                add_edge(doc_node_id, parent_node_id, "version_of", score=1.0)

        # 3. Document Relations Edges
        user_doc_ids = set(doc_dict.keys())
        # P0_04_SAFE_RELATION_RECONCILIATION: stale duplicate rows remain stored, not shown as current graph edges.
        relations = db.query(DocumentRelation).filter(
            (DocumentRelation.doc_a_id.in_(user_doc_ids)) & (DocumentRelation.doc_b_id.in_(user_doc_ids)),
            DocumentRelation.relation_type != "stale_duplicate",
        ).all()

        for rel in relations:
            node_a = f"doc_{rel.doc_a_id}"
            node_b = f"doc_{rel.doc_b_id}"
            if node_a in seen_node_ids and node_b in seen_node_ids:
                add_edge(node_a, node_b, rel.relation_type, score=rel.similarity_score, extra={"detected_by": rel.detected_by})

        return {
            "user_id": current_user.id,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }

    @staticmethod
    def get_document_history_timeline(
        db: Session, doc_uuid: str, current_user: User, lock_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fetch chronological event history timeline for a selected document."""
        doc_repo = DocumentRepository(db)
        doc = doc_repo.get_by_uuid(doc_uuid)
        from backend.core.permission_service import PermissionService
        if not doc or not PermissionService.can_read(db, current_user, doc):
            return {"document_uuid": doc_uuid, "events": []}

        if not PermissionService.check_access_lock(db, current_user, doc, lock_token):
            return {"document_uuid": doc_uuid, "events": [], "locked": True}

        # Query audit logs relating to this document
        audit_events = db.query(AuditLog).filter(
            AuditLog.resource_id == doc.uuid
        ).order_by(AuditLog.timestamp.asc()).all()

        events = []
        for log in audit_events:
            detail_dict = {}
            if log.detail:
                try:
                    detail_dict = json.loads(log.detail)
                    # Strip any sensitive info if present
                    detail_dict.pop("password", None)
                    detail_dict.pop("token", None)
                except Exception:
                    pass

            events.append({
                "id": log.id,
                "action": log.action,
                "timestamp": log.timestamp,
                "success": log.success,
                "detail": detail_dict
            })

        # Add initial upload milestone event if missing
        if not any(e["action"] == "DOCUMENT_UPLOAD" for e in events):
            events.insert(0, {
                "id": 0,
                "action": "DOCUMENT_UPLOAD",
                "timestamp": doc.uploaded_at,
                "success": 1,
                "detail": {"original_name": doc.original_name, "file_type": doc.file_type, "size_bytes": doc.size_bytes}
            })

        return {
            "document_uuid": doc.uuid,
            "original_name": doc.original_name,
            "display_name": doc.display_name or doc.original_name,
            "uploaded_at": doc.uploaded_at,
            "events": events
        }
