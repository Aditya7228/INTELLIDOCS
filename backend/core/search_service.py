from typing import List, Tuple, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from backend.algorithms.inverted_index import InvertedIndex
from backend.algorithms.trie import Trie
from backend.algorithms.graph import DocumentGraph
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document import DocumentModel
from backend.ai.embedding_engine import EmbeddingEngine
from backend.ai.vector_store import VectorStore

class SearchService:
    def __init__(
        self,
        inverted_index: InvertedIndex,
        trie: Trie,
        document_graph: DocumentGraph,
        embedding_engine: Optional[EmbeddingEngine] = None,
        vector_store: Optional[VectorStore] = None
    ):
        self.inverted_index = inverted_index
        self.trie = trie
        self.document_graph = document_graph
        self.embedding_engine = embedding_engine
        self.vector_store = vector_store

    def index_document(self, doc_id: int, text: str):
        if not text:
            return
        self.inverted_index.index_document(doc_id, text)
        self.document_graph.add_node(doc_id)

        # Insert tokens into Trie for autocomplete
        tokens = self.inverted_index.tokenize(text)
        for token in set(tokens):
            if len(token) >= 2:
                self.trie.insert(token, doc_id)

    def remove_document(self, doc_id: int):
        self.inverted_index.remove_document(doc_id)
        self.document_graph.remove_node(doc_id)

    def autocomplete(
        self,
        prefix: str,
        limit: int = 10,
        accessible_document_ids: Optional[Set[int]] = None,
    ) -> List[str]:
        # Fail closed if a caller forgets the authorization scope.
        if accessible_document_ids is None or not accessible_document_ids:
            return []
        return self.trie.search_prefix(
            prefix, limit=limit, accessible_doc_ids=accessible_document_ids
        )

    def hybrid_search(
        self,
        db: Session,
        query: str,
        current_user_id: int,
        page: int = 1,
        limit: int = 20,
        file_type: Optional[str] = None,
        category: Optional[str] = None,
        w_keyword: float = 0.5,
        w_semantic: float = 0.5,
        lock_token: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Execute Hybrid Search fusing TF-IDF keyword scores and SentenceTransformers FAISS vector similarity.
        Normalizes scores before weighted fusion.
        """
        repo = DocumentRepository(db)
        doc_scores: Dict[int, Dict[str, float]] = {}

        # 1. Keyword search via Inverted Index (TF-IDF length normalized)
        raw_keyword = self.inverted_index.search(query)
        max_kw_score = max([s for _, s in raw_keyword], default=1.0) if raw_keyword else 1.0

        for doc_id, kw_score in raw_keyword:
            norm_kw = kw_score / max(max_kw_score, 0.001)
            doc_scores[doc_id] = {"kw": norm_kw, "sem": 0.0}

        # 2. Semantic search via FAISS + SentenceTransformers
        if self.embedding_engine and self.embedding_engine.is_available() and self.vector_store and self.vector_store.is_available():
            q_vector = self.embedding_engine.encode(query)
            ann_hits = self.vector_store.search(q_vector, top_k=50)
            for doc_id, sem_score in ann_hits:
                sem_norm = max(0.0, min(1.0, float(sem_score)))
                if doc_id not in doc_scores:
                    doc_scores[doc_id] = {"kw": 0.0, "sem": sem_norm}
                else:
                    doc_scores[doc_id]["sem"] = sem_norm

        from backend.core.permission_service import PermissionService
        from backend.models.user import User
        accessible_ids = PermissionService.list_accessible_document_ids(db, current_user_id)
        actor = db.query(User).filter(User.id == current_user_id).first()
        if not actor:
            return [], 0

        hits = []
        for doc_id, score_dict in doc_scores.items():
            doc = repo.get_by_id(doc_id)
            if not doc or doc.is_deleted or (doc_id not in accessible_ids and doc.owner_id != current_user_id):
                continue
            if not PermissionService.check_access_lock(db, actor, doc, lock_token):
                continue
            if file_type and doc.file_type != file_type:
                continue
            if category:
                effective_category = doc.category
                if doc.owner_id != current_user_id:
                    try:
                        from backend.core.document_view_service import get_preference
                        pref = get_preference(db, current_user_id, doc.id)
                        if pref and pref.category:
                            effective_category = pref.category
                    except Exception:
                        pass
                if effective_category != category:
                    continue

            final_score = round(w_keyword * score_dict["kw"] + w_semantic * score_dict["sem"], 4)
            snippet = self._generate_snippet(doc.extracted_text or "", query)

            hits.append({
                "document": doc,
                "score": final_score,
                "keyword_score": round(score_dict["kw"], 4),
                "semantic_score": round(score_dict["sem"], 4),
                "snippet": snippet
            })

        hits.sort(key=lambda x: x["score"], reverse=True)
        total = len(hits)
        offset = (page - 1) * limit
        paged_hits = hits[offset:offset + limit]
        return paged_hits, total

    def keyword_search(
        self,
        db: Session,
        query: str,
        current_user_id: int,
        page: int = 1,
        limit: int = 20,
        file_type: Optional[str] = None,
        category: Optional[str] = None,
        lock_token: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        return self.hybrid_search(
            db=db, query=query, current_user_id=current_user_id,
            page=page, limit=limit, file_type=file_type, category=category,
            w_keyword=0.5, w_semantic=0.5, lock_token=lock_token
        )

    def rebuild_index(self, db: Session, user_id: Optional[int] = None) -> int:
        """INTELLIDOCS_REBUILD_SEARCH_INDEX_V1: rebuild process-local keyword and autocomplete indexes.

        The underlying indexes are shared by the application process, so a rebuild
        must load all active documents (not only one user's documents). Authorization
        remains enforced by the search endpoints and autocomplete's accessible-ID scope.
        ``user_id`` is retained for call-site compatibility with earlier revisions.
        """
        # Clear existing keyword postings and trie contents so repeat rebuilds are
        # idempotent and cannot increment term frequencies a second time.
        self.inverted_index._index.clear()
        self.inverted_index._doc_lengths.clear()
        self.inverted_index._total_docs = 0
        self.trie.root = type(self.trie.root)()

        docs = (
            db.query(DocumentModel)
            .filter(DocumentModel.is_deleted == 0)
            .order_by(DocumentModel.id.asc())
            .all()
        )
        active_ids = {doc.id for doc in docs}

        # Remove stale graph nodes for deleted documents while preserving edges
        # between still-active documents. Indexing below adds missing active nodes.
        for stale_id in set(self.document_graph._adj) - active_ids:
            self.document_graph.remove_node(stale_id)

        indexed_count = 0
        for doc in docs:
            self.document_graph.add_node(doc.id)
            if doc.extracted_text:
                self.index_document(doc.id, doc.extracted_text)
                indexed_count += 1

        return indexed_count

    def _generate_snippet(self, text: str, query: str, length: int = 160) -> str:
        if not text:
            return ""
        tokens = [t.lower() for t in self.inverted_index.tokenize(query)]
        text_lower = text.lower()

        match_idx = -1
        for token in tokens:
            idx = text_lower.find(token)
            if idx != -1:
                match_idx = idx
                break

        if match_idx == -1:
            return text[:length] + ("..." if len(text) > length else "")

        start = max(0, match_idx - 40)
        end = min(len(text), match_idx + length - 40)
        snippet = text[start:end]
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        return snippet
