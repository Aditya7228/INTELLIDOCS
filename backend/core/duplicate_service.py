import re
import difflib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session
from backend.algorithms.lsh import MinHashLSH
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document import DocumentModel
from backend.utils.perceptual_hash import dhash_similarity, compute_pdf_page_dhashes, multi_page_visual_similarity
from backend.ai.embedding_engine import EmbeddingEngine
from backend.ai.vector_store import VectorStore
from backend.core.duplicate_policy import (
    classify_duplicate_evidence,
    is_actionable_duplicate,
    DUPLICATE_NEAR_THRESHOLD,
)


# Any strongest similarity evidence strictly greater than this value is
# considered actionable near-duplicate intelligence.
# Legacy compatibility alias. Final duplicate decisions come from duplicate_policy.py.
DUPLICATE_EVIDENCE_THRESHOLD = DUPLICATE_NEAR_THRESHOLD

def normalize_text_for_comparison(text: str) -> str:
    """Normalize text by collapsing whitespace, stripping punctuation and lowercasing."""
    if not text:
        return ""
    cleaned = re.sub(r"[^\w\s]", "", text.lower())
    return re.sub(r"\s+", " ", cleaned).strip()

@dataclass
class EvidenceBreakdown:
    doc_a_id: int
    doc_b_id: int
    doc_b_uuid: str
    doc_b_name: str
    relation_type: str
    confidence: float
    scores: Dict[str, float] = field(default_factory=dict)
    detection_methods: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)

class DuplicateService:
    def __init__(
        self,
        lsh_index: MinHashLSH,
        embedding_engine: Optional[EmbeddingEngine] = None,
        vector_store: Optional[VectorStore] = None
    ):
        self.lsh_index = lsh_index
        self.embedding_engine = embedding_engine
        self.vector_store = vector_store

    def evaluate_pair(self, doc_a: DocumentModel, doc_b: DocumentModel) -> EvidenceBreakdown:
        """
        Evaluate ALL 5 levels of similarity evidence for a document pair without early returns.
        Returns a structured EvidenceBreakdown.
        """
        scores: Dict[str, float] = {}
        methods: List[str] = []
        evidence: List[str] = []

        # 1. Level 1: SHA-256 Byte Match
        sha_match = bool(doc_a.sha256_hash and doc_b.sha256_hash and doc_a.sha256_hash == doc_b.sha256_hash)
        scores["sha256_match"] = 1.0 if sha_match else 0.0
        if sha_match:
            methods.append("SHA-256 Digest")
            evidence.append(f"Byte-identical SHA-256 hash ({doc_a.sha256_hash[:12]}...)")

        # 2. Level 2: Normalized Extracted Content Comparison
        norm_a = normalize_text_for_comparison(doc_a.extracted_text or "")
        norm_b = normalize_text_for_comparison(doc_b.extracted_text or "")

        norm_sim = 0.0
        if norm_a and norm_b:
            if norm_a == norm_b:
                norm_sim = 1.0
            else:
                # SequenceMatcher ratio for quick similarity
                sm = difflib.SequenceMatcher(None, norm_a[:2000], norm_b[:2000])
                norm_sim = round(sm.ratio(), 4)

        scores["normalized_content_sim"] = norm_sim
        if norm_sim >= 0.85:
            methods.append("Normalized Text Matching")
            evidence.append(f"Text content matches with {round(norm_sim * 100, 1)}% similarity")

        # 3. Level 3: MinHash / LSH Jaccard Similarity
        minhash_sim = 0.0
        sig_a = self.lsh_index._signatures.get(doc_a.id)
        sig_b = self.lsh_index._signatures.get(doc_b.id)
        if not sig_a and doc_a.extracted_text:
            sig_a = self.lsh_index.compute_signature(self.lsh_index.get_shingles(doc_a.extracted_text))
        if not sig_b and doc_b.extracted_text:
            sig_b = self.lsh_index.compute_signature(self.lsh_index.get_shingles(doc_b.extracted_text))

        if sig_a and sig_b:
            minhash_sim = round(self.lsh_index.jaccard_similarity(sig_a, sig_b), 4)

        scores["minhash_lsh_sim"] = minhash_sim
        if minhash_sim >= 0.60:
            methods.append("MinHash/LSH Shingling")
            evidence.append(f"MinHash n-gram shingle similarity of {round(minhash_sim * 100, 1)}%")

        # 4. Level 4: SentenceTransformers Dense Embedding Vector Similarity
        semantic_sim = 0.0
        if self.embedding_engine and self.embedding_engine.is_available():
            if doc_a.extracted_text and doc_b.extracted_text:
                vec_a = self.embedding_engine.encode(doc_a.extracted_text)
                vec_b = self.embedding_engine.encode(doc_b.extracted_text)
                dot_prod = float(sum(a * b for a, b in zip(vec_a, vec_b)))
                semantic_sim = max(0.0, min(1.0, round(dot_prod, 4)))

        scores["semantic_embedding_sim"] = semantic_sim
        if semantic_sim >= 0.70:
            methods.append("SentenceTransformers Dense Vector")
            evidence.append(f"Semantic embedding similarity score of {round(semantic_sim * 100, 1)}%")

        # 5. Level 5: OCR & Visual Perceptual Image Similarity
        ocr_sim = norm_sim if (doc_a.has_ocr or doc_b.has_ocr) else 0.0
        scores["ocr_text_sim"] = ocr_sim

        visual_sim = 0.0
        if doc_a.perceptual_hash and doc_b.perceptual_hash:
            visual_sim = round(dhash_similarity(doc_a.perceptual_hash, doc_b.perceptual_hash), 4)

        scores["visual_perceptual_sim"] = visual_sim
        if visual_sim >= 0.80:
            methods.append("Perceptual dHash")
            evidence.append(f"Visual perceptual dHash similarity of {round(visual_sim * 100, 1)}%")

        # Classify relationship based on combined evidence.
        # A pair becomes actionable duplicate intelligence when ANY evidence
        # channel is strictly greater than 0.45. Keep stronger labels for
        # exact/content matches so the existing hierarchy remains intact.
        evidence_score = max(norm_sim, minhash_sim, semantic_sim, visual_sim)
        relation_type = "related"
        confidence = evidence_score

        if sha_match:
            relation_type = "exact_duplicate"
            confidence = 1.0
        elif norm_sim >= 0.98:
            relation_type = "content_duplicate"
            confidence = norm_sim
        elif evidence_score > DUPLICATE_EVIDENCE_THRESHOLD:
            relation_type = "near_duplicate"
            confidence = evidence_score
        elif (doc_a.original_name and doc_b.original_name and
              self._check_version_naming_pattern(doc_a.original_name, doc_b.original_name)) and (semantic_sim >= 0.75 or norm_sim >= 0.65):
            relation_type = "possible_version"
            confidence = max(semantic_sim, norm_sim)
        elif visual_sim >= 0.80:
            relation_type = "visual_similarity"
            confidence = visual_sim
        elif semantic_sim >= 0.70:
            relation_type = "semantic_similarity"
            confidence = semantic_sim
        elif evidence_score >= 0.0:
            relation_type = "related"
            confidence = evidence_score

        return EvidenceBreakdown(
            doc_a_id=doc_a.id,
            doc_b_id=doc_b.id,
            doc_b_uuid=doc_b.uuid,
            doc_b_name=doc_b.original_name,
            relation_type=relation_type,
            confidence=confidence,
            scores=scores,
            detection_methods=methods,
            supporting_evidence=evidence
        )

    def _check_version_naming_pattern(self, name1: str, name2: str) -> bool:
        """Check if two filenames suggest a revision relationship (e.g. doc_v1 vs doc_v2)."""
        clean1 = re.sub(r"[\d_vV\.\-]+", "", name1.lower())
        clean2 = re.sub(r"[\d_vV\.\-]+", "", name2.lower())
        return clean1 == clean2 and len(clean1) > 3

    def analyze_all_candidates(self, db: Session, target_doc: DocumentModel, owner_id: int) -> List[EvidenceBreakdown]:
        """Find and evaluate all potential duplicate/relation candidates for a document."""
        repo = DocumentRepository(db)

        candidate_ids: Set[int] = set()

        # Gather candidate IDs from all detection indexes
        # 1. SHA-256 matches
        exacts = repo.get_by_sha256(target_doc.sha256_hash)
        for e in exacts:
            if e.id != target_doc.id and e.owner_id == owner_id:
                candidate_ids.add(e.id)

        # 2. MinHash LSH candidates
        if target_doc.extracted_text:
            lsh_cands = self.lsh_index.query_candidates(target_doc.extracted_text)
            for cid in lsh_cands:
                if cid != target_doc.id:
                    candidate_ids.add(cid)

        # 3. VectorStore ANN candidates
        if self.vector_store and self.vector_store.is_available() and self.embedding_engine and target_doc.extracted_text:
            vec = self.embedding_engine.encode(target_doc.extracted_text)
            ann_results = self.vector_store.search(vec, top_k=15)
            for cid, score in ann_results:
                if cid != target_doc.id:
                    candidate_ids.add(cid)

        # 4. Persistent visual candidate discovery
        #
        # Visual dHashes are persisted on DocumentModel, but the LSH/ANN
        # indexes are process-local. After a restart they may not contain
        # older documents, so visual duplicates must also be discovered
        # directly from the owner's persisted perceptual hashes.
        if target_doc.perceptual_hash:
            visual_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.id.in_(accessible_ids),
                    DocumentModel.is_deleted == 0,
                    DocumentModel.id != target_doc.id,
                    DocumentModel.perceptual_hash.isnot(None),
                )
                .yield_per(200)
            )

            for visual_doc in visual_docs:
                try:
                    visual_sim = dhash_similarity(
                        target_doc.perceptual_hash,
                        visual_doc.perceptual_hash,
                    )
                    if visual_sim >= 0.80:
                        candidate_ids.add(visual_doc.id)
                except Exception:
                    continue

        # 5. Persistent textual candidate discovery
        #
        # MinHash/LSH is also process-local. Use a lightweight full-owner
        # text scan to discover strong textual candidates that may have been
        # missed after a restart or were never inserted into the index.
        if target_doc.extracted_text:
            target_norm = normalize_text_for_comparison(
                target_doc.extracted_text or ""
            )

            if target_norm:
                text_docs = (
                    repo.db.query(DocumentModel)
                    .filter(
                        DocumentModel.owner_id == owner_id,
                        DocumentModel.is_deleted == 0,
                        DocumentModel.id != target_doc.id,
                        DocumentModel.extracted_text.isnot(None),
                    )
                    .yield_per(200)
                )

                for text_doc in text_docs:
                    candidate_text = normalize_text_for_comparison(
                        text_doc.extracted_text or ""
                    )
                    if not candidate_text:
                        continue

                    if target_norm == candidate_text:
                        candidate_ids.add(text_doc.id)
                        continue

                    try:
                        text_sim = difflib.SequenceMatcher(
                            None,
                            target_norm[:2000],
                            candidate_text[:2000],
                        ).ratio()

                        if text_sim >= 0.80:
                            candidate_ids.add(text_doc.id)
                    except Exception:
                        continue

        # 6. Bounded general fallback for broader relationship discovery.
        # Keep this bounded so normal uploads do not evaluate every document.
        user_docs, _ = repo.list_user_documents(owner_id=owner_id, limit=100)
        for ud in user_docs:
            if ud.id != target_doc.id:
                candidate_ids.add(ud.id)

        results: List[EvidenceBreakdown] = []
        for cand_id in candidate_ids:
            cand_doc = repo.get_by_id(cand_id)
            if not cand_doc or cand_doc.owner_id != owner_id or cand_doc.is_deleted:
                continue

            eb = self.evaluate_pair(target_doc, cand_doc)
            # Retain any candidate above the actionable duplicate threshold.
            # This must match evaluate_pair() so a >0.45 pair is not silently
            # discarded before the API/alert layer can see it.
            if eb.confidence > DUPLICATE_EVIDENCE_THRESHOLD or eb.scores.get("sha256_match", 0) > 0:
                results.append(eb)
                # Persist relation in DB
                repo.create_relation(
                    doc_a_id=target_doc.id,
                    doc_b_id=cand_doc.id,
                    relation_type=eb.relation_type,
                    score=eb.confidence,
                    detected_by=", ".join(eb.detection_methods) if eb.detection_methods else "system"
                )

        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

# --- DUPLICATE_THRESHOLD_V9_20261008 ---------------------------------------
# Actionable duplicate policy:
#   >= 0.90 text/MinHash similarity -> exact_duplicate
#   >= 0.65 text/MinHash similarity -> near_duplicate
#   < 0.65 -> not returned by duplicate candidate APIs
# Broad all-document fallback is intentionally disabled. Candidate discovery
# relies on exact SHA, MinHash/LSH, ANN, persistent visual hashes, and already
# persisted high-confidence relations instead of evaluating every pair.

_DUPLICATE_V9_EXACT_THRESHOLD = 0.90
_DUPLICATE_V9_NEAR_THRESHOLD = 0.65
_DUPLICATE_V9_PERSISTED_VISUAL_THRESHOLD = 0.85


_DUPLICATE_V9_ORIGINAL_EVALUATE_PAIR = DuplicateService.evaluate_pair


def _duplicate_v9_evaluate_pair(self, doc_a, doc_b):
    eb = _DUPLICATE_V9_ORIGINAL_EVALUATE_PAIR(self, doc_a, doc_b)

    text_score = max(
        float(eb.scores.get("normalized_content_sim", 0.0) or 0.0),
        float(eb.scores.get("minhash_lsh_sim", 0.0) or 0.0),
    )
    visual_score = float(eb.scores.get("visual_perceptual_sim", 0.0) or 0.0)
    semantic_score = float(eb.scores.get("semantic_embedding_sim", 0.0) or 0.0)

    # SHA remains the strongest possible exact proof.
    if float(eb.scores.get("sha256_match", 0.0) or 0.0) > 0.0:
        eb.relation_type = "exact_duplicate"
        eb.confidence = 1.0
        return eb

    # User-requested duplicate bands. We deliberately do NOT use semantic
    # similarity alone to call something a near-duplicate; that signal can
    # correctly find related documents that are not duplicates.
    if text_score >= _DUPLICATE_V9_EXACT_THRESHOLD:
        eb.relation_type = "exact_duplicate"
        eb.confidence = text_score
    elif text_score >= _DUPLICATE_V9_NEAR_THRESHOLD:
        eb.relation_type = "near_duplicate"
        eb.confidence = text_score
    elif visual_score >= _DUPLICATE_V9_PERSISTED_VISUAL_THRESHOLD:
        eb.relation_type = "visual_similarity"
        eb.confidence = visual_score
    elif (
        eb.relation_type == "possible_version"
        and max(text_score, semantic_score) >= _DUPLICATE_V9_NEAR_THRESHOLD
    ):
        # Keep version intelligence only when it also clears the actionable
        # 0.65 floor.
        eb.relation_type = "possible_version"
        eb.confidence = max(text_score, semantic_score)
    else:
        eb.relation_type = "related"
        eb.confidence = max(0.50, min(max(text_score, visual_score, semantic_score), 0.64))

    return eb


_DUPLICATE_V9_ORIGINAL_ANALYZE_ALL_CANDIDATES = DuplicateService.analyze_all_candidates


def _duplicate_v9_analyze_all_candidates(self, db, target_doc, owner_id):
    repo = DocumentRepository(db)
    candidate_ids: Set[int] = set()

    # Exact SHA lookup is constant-time-ish at the repository/index level and
    # should always be retained.
    if target_doc.sha256_hash:
        for e in repo.get_by_sha256(target_doc.sha256_hash):
            if e.id != target_doc.id and e.owner_id == owner_id and not e.is_deleted:
                candidate_ids.add(e.id)

    # Rebuild the process-local LSH index once after a server restart. This is
    # indexing, not pairwise comparison; it prevents the old "compare every
    # document with every other document" fallback while keeping old documents
    # discoverable for future duplicate checks.
    if not self.lsh_index._signatures:
        try:
            # 32 bands x 4 rows improves candidate recall around a 0.65 Jaccard
            # threshold while keeping MinHash itself at 128 permutations.
            self.lsh_index.num_bands = 32
            self.lsh_index.rows_per_band = 4
            bootstrap_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.is_deleted == 0,
                    DocumentModel.extracted_text.isnot(None),
                )
                .yield_per(200)
            )
            for indexed_doc in bootstrap_docs:
                text = indexed_doc.extracted_text or ""
                if text.strip():
                    self.lsh_index.add(indexed_doc.id, text)
        except Exception:
            # Duplicate detection must never break normal document operations.
            pass

    if target_doc.extracted_text:
        try:
            for cid in self.lsh_index.query_candidates(target_doc.extracted_text):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # ANN remains bounded to top-k and is useful for highly paraphrased text.
    if (
        self.vector_store
        and self.vector_store.is_available()
        and self.embedding_engine
        and target_doc.extracted_text
    ):
        try:
            vec = self.embedding_engine.encode(target_doc.extracted_text)
            for cid, _score in self.vector_store.search(vec, top_k=15):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # Persistent visual discovery is retained only for documents that actually
    # have a perceptual hash. No generic document fallback is used.
    if target_doc.perceptual_hash:
        try:
            visual_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.owner_id == owner_id,
                    DocumentModel.is_deleted == 0,
                    DocumentModel.id != target_doc.id,
                    DocumentModel.perceptual_hash.isnot(None),
                )
                .yield_per(200)
            )
            for visual_doc in visual_docs:
                try:
                    visual_sim = dhash_similarity(
                        target_doc.perceptual_hash,
                        visual_doc.perceptual_hash,
                    )
                    if visual_sim >= _DUPLICATE_V9_PERSISTED_VISUAL_THRESHOLD:
                        candidate_ids.add(visual_doc.id)
                except Exception:
                    continue
        except Exception:
            pass

    # Reuse already persisted actionable relations as a cheap durable candidate
    # source after restarts. We do not resurrect sub-0.65 relationships.
    try:
        from backend.models.document_relation import DocumentRelation
        persisted = (
            repo.db.query(DocumentRelation)
            .filter(
                (DocumentRelation.doc_a_id == target_doc.id)
                | (DocumentRelation.doc_b_id == target_doc.id),
                DocumentRelation.similarity_score >= _DUPLICATE_V9_NEAR_THRESHOLD,
            )
            .all()
        )
        for rel in persisted:
            other_id = rel.doc_b_id if rel.doc_a_id == target_doc.id else rel.doc_a_id
            if other_id != target_doc.id:
                candidate_ids.add(other_id)
    except Exception:
        pass

    results: List[EvidenceBreakdown] = []
    actionable_types = {
        "exact_duplicate",
        "near_duplicate",
        "visual_similarity",
        "possible_version",
    }

    for cand_id in candidate_ids:
        cand_doc = repo.get_by_id(cand_id)
        if not cand_doc or cand_doc.id not in accessible_ids or cand_doc.is_deleted:
            continue

        try:
            eb = self.evaluate_pair(target_doc, cand_doc)
        except Exception:
            continue

        # Hard 0.65 floor: lower-confidence relationships disappear from
        # duplicate results and are never persisted by the fresh evaluation.
        if eb.confidence < _DUPLICATE_V9_NEAR_THRESHOLD:
            continue
        if eb.relation_type not in actionable_types:
            continue

        results.append(eb)
        try:
            repo.create_relation(
                doc_a_id=target_doc.id,
                doc_b_id=cand_doc.id,
                relation_type=eb.relation_type,
                score=eb.confidence,
                detected_by=", ".join(eb.detection_methods) if eb.detection_methods else "system",
            )
        except Exception:
            pass

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


DuplicateService.evaluate_pair = _duplicate_v9_evaluate_pair
DuplicateService.analyze_all_candidates = _duplicate_v9_analyze_all_candidates
# --- END DUPLICATE_THRESHOLD_V9_20261008 -----------------------------------

# --- DUPLICATE_POLICY_V10_20261008 ---------------------------------------
# Actionable duplicate policy:
#   >= 0.90 text OR visual similarity -> exact_duplicate
#   >= 0.65 text OR visual similarity -> near_duplicate
#   < 0.65 -> not returned by duplicate candidate APIs
# Broad all-document fallback is intentionally disabled. Candidate discovery
# relies on exact SHA, MinHash/LSH, ANN, persistent visual hashes, and already
# persisted high-confidence relations instead of evaluating every pair.

_DUPLICATE_V10_EXACT_THRESHOLD = 0.90
_DUPLICATE_V10_NEAR_THRESHOLD = 0.65
_DUPLICATE_V10_PERSISTED_VISUAL_THRESHOLD = 0.65


_DUPLICATE_V10_ORIGINAL_EVALUATE_PAIR = DuplicateService.evaluate_pair


def _duplicate_v9_evaluate_pair(self, doc_a, doc_b):
    eb = _DUPLICATE_V10_ORIGINAL_EVALUATE_PAIR(self, doc_a, doc_b)

    text_score = max(
        float(eb.scores.get("normalized_content_sim", 0.0) or 0.0),
        float(eb.scores.get("minhash_lsh_sim", 0.0) or 0.0),
    )
    visual_score = float(eb.scores.get("visual_perceptual_sim", 0.0) or 0.0)
    semantic_score = float(eb.scores.get("semantic_embedding_sim", 0.0) or 0.0)

    # SHA remains the strongest possible exact proof.
    if float(eb.scores.get("sha256_match", 0.0) or 0.0) > 0.0:
        eb.relation_type = "exact_duplicate"
        eb.confidence = 1.0
        return eb

    # Actionable duplicate score is modality-agnostic: textual similarity OR
    # visual/image similarity can qualify. Semantic similarity alone is never
    # promoted to duplicate because related documents are not necessarily
    # duplicates. The strongest qualifying modality wins.
    duplicate_score = max(text_score, visual_score)
    if duplicate_score >= _DUPLICATE_V10_EXACT_THRESHOLD:
        eb.relation_type = "exact_duplicate"
        eb.confidence = duplicate_score
    elif duplicate_score >= _DUPLICATE_V10_NEAR_THRESHOLD:
        eb.relation_type = "near_duplicate"
        eb.confidence = duplicate_score
    elif (
        eb.relation_type == "possible_version"
        and text_score >= _DUPLICATE_V10_NEAR_THRESHOLD
    ):
        # Version intelligence remains textual and actionable only when the
        # text signal itself clears the 0.65 duplicate floor.
        eb.relation_type = "possible_version"
        eb.confidence = text_score
    else:
        eb.relation_type = "related"
        eb.confidence = max(0.50, min(max(text_score, visual_score, semantic_score), 0.64))

    return eb


_DUPLICATE_V10_ORIGINAL_ANALYZE_ALL_CANDIDATES = DuplicateService.analyze_all_candidates


def _duplicate_v9_analyze_all_candidates(self, db, target_doc, owner_id):
    repo = DocumentRepository(db)
    candidate_ids: Set[int] = set()

    # Exact SHA lookup is constant-time-ish at the repository/index level and
    # should always be retained.
    if target_doc.sha256_hash:
        for e in repo.get_by_sha256(target_doc.sha256_hash):
            if e.id != target_doc.id and e.owner_id == owner_id and not e.is_deleted:
                candidate_ids.add(e.id)

    # Rebuild the process-local LSH index once after a server restart. This is
    # indexing, not pairwise comparison; it prevents the old "compare every
    # document with every other document" fallback while keeping old documents
    # discoverable for future duplicate checks.
    if not self.lsh_index._signatures:
        try:
            # 32 bands x 4 rows improves candidate recall around a 0.65 Jaccard
            # threshold while keeping MinHash itself at 128 permutations.
            self.lsh_index.num_bands = 32
            self.lsh_index.rows_per_band = 4
            bootstrap_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.is_deleted == 0,
                    DocumentModel.extracted_text.isnot(None),
                )
                .yield_per(200)
            )
            for indexed_doc in bootstrap_docs:
                text = indexed_doc.extracted_text or ""
                if text.strip():
                    self.lsh_index.add(indexed_doc.id, text)
        except Exception:
            # Duplicate detection must never break normal document operations.
            pass

    if target_doc.extracted_text:
        try:
            for cid in self.lsh_index.query_candidates(target_doc.extracted_text):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # ANN remains bounded to top-k and is useful for highly paraphrased text.
    if (
        self.vector_store
        and self.vector_store.is_available()
        and self.embedding_engine
        and target_doc.extracted_text
    ):
        try:
            vec = self.embedding_engine.encode(target_doc.extracted_text)
            for cid, _score in self.vector_store.search(vec, top_k=15):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # Persistent visual discovery is retained for documents that actually have
    # perceptual hashes. The same 0.65/0.90 policy is used for images as text;
    # there is no generic all-document fallback.
    if target_doc.perceptual_hash:
        try:
            visual_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.owner_id == owner_id,
                    DocumentModel.is_deleted == 0,
                    DocumentModel.id != target_doc.id,
                    DocumentModel.perceptual_hash.isnot(None),
                )
                .yield_per(200)
            )
            for visual_doc in visual_docs:
                try:
                    visual_sim = dhash_similarity(
                        target_doc.perceptual_hash,
                        visual_doc.perceptual_hash,
                    )
                    if visual_sim >= _DUPLICATE_V10_PERSISTED_VISUAL_THRESHOLD:
                        candidate_ids.add(visual_doc.id)
                except Exception:
                    continue
        except Exception:
            pass

    # Reuse already persisted actionable relations as a cheap durable candidate
    # source after restarts. We do not resurrect sub-0.65 relationships.
    try:
        from backend.models.document_relation import DocumentRelation
        persisted = (
            repo.db.query(DocumentRelation)
            .filter(
                (DocumentRelation.doc_a_id == target_doc.id)
                | (DocumentRelation.doc_b_id == target_doc.id),
                DocumentRelation.similarity_score >= _DUPLICATE_V10_NEAR_THRESHOLD,
            )
            .all()
        )
        for rel in persisted:
            other_id = rel.doc_b_id if rel.doc_a_id == target_doc.id else rel.doc_a_id
            if other_id != target_doc.id:
                candidate_ids.add(other_id)
    except Exception:
        pass

    results: List[EvidenceBreakdown] = []
    actionable_types = {
        "exact_duplicate",
        "near_duplicate",
        "visual_similarity",
        "possible_version",
    }

    for cand_id in candidate_ids:
        cand_doc = repo.get_by_id(cand_id)
        if not cand_doc or cand_doc.owner_id != owner_id or cand_doc.is_deleted:
            continue

        try:
            eb = self.evaluate_pair(target_doc, cand_doc)
        except Exception:
            continue

        # Hard 0.65 floor: lower-confidence relationships disappear from duplicate
        # results and are never persisted by the fresh evaluation.
        if eb.confidence < _DUPLICATE_V10_NEAR_THRESHOLD:
            continue
        if eb.relation_type not in actionable_types:
            continue

        results.append(eb)
        try:
            repo.create_relation(
                doc_a_id=target_doc.id,
                doc_b_id=cand_doc.id,
                relation_type=eb.relation_type,
                score=eb.confidence,
                detected_by=", ".join(eb.detection_methods) if eb.detection_methods else "system",
            )
        except Exception:
            pass

    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


DuplicateService.evaluate_pair = _duplicate_v9_evaluate_pair
DuplicateService.analyze_all_candidates = _duplicate_v9_analyze_all_candidates
# --- END DUPLICATE_POLICY_V10_20261008 -----------------------------------

# --- P0_03_CANDIDATE_DISCOVERY ---------------------------------------------
def _duplicate_p0_03_discover_candidate_ids(self, db, target_doc, owner_id):
    """Discover likely duplicate candidates without deciding duplication.

    Discovery is recall-oriented: exact SHA, process-local LSH, bounded ANN,
    persisted visual hashes, and persisted actionable relations may contribute
    candidate IDs. No similarity threshold here is a final duplicate decision;
    every candidate is re-evaluated by the authoritative policy afterward.

    The former broad all-document fallback is intentionally absent.
    """
    repo = DocumentRepository(db)
    candidate_ids: Set[int] = set()
    from backend.core.permission_service import PermissionService
    try:
        accessible_ids = set(PermissionService.list_accessible_document_ids(db, int(owner_id)))
    except Exception:
        # Fail closed: do not fall back to cross-user duplicate discovery.
        return set()
    if int(target_doc.id) not in accessible_ids:
        return set()

    # 1. Exact byte-match candidates.
    if target_doc.sha256_hash:
        for doc in repo.get_by_sha256(target_doc.sha256_hash):
            if doc.id != target_doc.id and doc.id in accessible_ids and not doc.is_deleted:
                candidate_ids.add(doc.id)

    # 2. Rebuild process-local LSH once after restart. This is index bootstrap,
    # not pairwise duplicate evaluation.
    if not self.lsh_index._signatures:
        try:
            self.lsh_index.num_bands = 32
            self.lsh_index.rows_per_band = 4
            bootstrap_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.is_deleted == 0,
                    DocumentModel.extracted_text.isnot(None),
                )
                .yield_per(200)
            )
            for indexed_doc in bootstrap_docs:
                text = indexed_doc.extracted_text or ""
                if text.strip():
                    self.lsh_index.add(indexed_doc.id, text)
        except Exception:
            pass

    # 3. MinHash/LSH candidates.
    if target_doc.extracted_text:
        try:
            for cid in self.lsh_index.query_candidates(target_doc.extracted_text):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # 4. Bounded ANN candidates. Semantic similarity is discovery-only and can
    # never become a duplicate merely by appearing here.
    if (
        self.vector_store
        and self.vector_store.is_available()
        and self.embedding_engine
        and target_doc.extracted_text
    ):
        try:
            vec = self.embedding_engine.encode(target_doc.extracted_text)
            for cid, _score in self.vector_store.search(vec, top_k=15):
                if cid != target_doc.id:
                    candidate_ids.add(cid)
        except Exception:
            pass

    # 5. Persisted perceptual hashes preserve visual-discovery recall across
    # process restarts. The threshold only gates candidate admission; final
    # visual duplicate classification remains the authoritative 0.65/0.90 rule.
    if target_doc.perceptual_hash:
        try:
            visual_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.id.in_(accessible_ids),
                    DocumentModel.is_deleted == 0,
                    DocumentModel.id != target_doc.id,
                    DocumentModel.perceptual_hash.isnot(None),
                )
                .yield_per(200)
            )
            for visual_doc in visual_docs:
                try:
                    visual_sim = dhash_similarity(
                        target_doc.perceptual_hash, visual_doc.perceptual_hash
                    )
                    if visual_sim >= DUPLICATE_NEAR_THRESHOLD:
                        candidate_ids.add(visual_doc.id)
                except Exception:
                    continue
        except Exception:
            pass

    # 5b. Owner-scoped persistent text sweep closes gaps left by process-local LSH/ANN.
    # Discovery only: the authoritative policy below still requires >=0.65 strict
    # text/OCR/visual evidence (or exact SHA-256) before returning a duplicate.
    # The query is scoped to this user's active library; other users are never scanned.
    if target_doc.extracted_text and target_doc.extracted_text.strip():
        try:
            target_norm = normalize_text_for_comparison(target_doc.extracted_text)
            target_shingles = set(self.lsh_index.get_shingles(target_doc.extracted_text)) if target_norm else set()
            text_docs = (
                repo.db.query(DocumentModel)
                .filter(
                    DocumentModel.id.in_(accessible_ids),
                    DocumentModel.is_deleted == 0,
                    DocumentModel.id != target_doc.id,
                    DocumentModel.extracted_text.isnot(None),
                )
                .yield_per(200)
            )
            for text_doc in text_docs:
                candidate_text = text_doc.extracted_text or ""
                candidate_norm = normalize_text_for_comparison(candidate_text)
                if not candidate_norm:
                    continue
                if target_norm == candidate_norm:
                    candidate_ids.add(text_doc.id)
                    continue
                seq_score = difflib.SequenceMatcher(
                    None, target_norm[:4000], candidate_norm[:4000]
                ).ratio()
                if seq_score >= 0.45:
                    candidate_ids.add(text_doc.id)
                    continue
                try:
                    candidate_shingles = set(self.lsh_index.get_shingles(candidate_text))
                    if target_shingles and candidate_shingles:
                        union = target_shingles | candidate_shingles
                        overlap = len(target_shingles & candidate_shingles) / len(union) if union else 0.0
                        if overlap >= 0.35:
                            candidate_ids.add(text_doc.id)
                except Exception:
                    continue
        except Exception:
            # Preserve exact-SHA, LSH, ANN, visual, and persisted-relation discovery if a legacy row fails.
            pass

    # 6. Persisted relations are treated as candidate hints only. Current pair
    # evidence is always recalculated before a result is exposed.
    try:
        from backend.models.document_relation import DocumentRelation
        persisted_duplicate_types = {
            "duplicate", "content_duplicate", "exact_duplicate",
            "near_duplicate", "visual_similarity", "stale_duplicate",
            "semantic_similarity",
        }
        persisted = (
            repo.db.query(DocumentRelation)
            .filter(
                (DocumentRelation.doc_a_id == target_doc.id)
                | (DocumentRelation.doc_b_id == target_doc.id),
                DocumentRelation.relation_type.in_(persisted_duplicate_types),
            )
            .all()
        )
        for rel in persisted:
            other_id = (
                rel.doc_b_id if rel.doc_a_id == target_doc.id else rel.doc_a_id
            )
            if other_id != target_doc.id:
                candidate_ids.add(other_id)
    except Exception:
        pass

    return candidate_ids

# --- DUPLICATE_POLICY_V11_20261008_SERVICE ---------------------------------
# Final backend classification boundary. Evidence measurement and candidate
# discovery remain separate; this block is responsible only for mapping
# measured evidence to the authoritative duplicate state.

_DUPLICATE_V11_ORIGINAL_EVALUATE_PAIR = DuplicateService.evaluate_pair


def _duplicate_v11_reclassify(eb):
    classification = classify_duplicate_evidence(eb.scores or {})
    eb.relation_type = classification.relation_type
    eb.confidence = classification.confidence
    return eb


def _duplicate_v11_evaluate_pair(self, doc_a, doc_b):
    eb = _DUPLICATE_V11_ORIGINAL_EVALUATE_PAIR(self, doc_a, doc_b)
    return _duplicate_v11_reclassify(eb)


def _duplicate_v11_analyze_all_candidates(self, db, target_doc, owner_id, lock_token=None, lock_tokens=None):
    # Candidate discovery is deliberately independent from final duplicate
    # classification. ANN/LSH/visual/persisted-relation hits are only leads;
    # the authoritative policy decides whether a lead is actionable.
    from backend.core.permission_service import PermissionService
    from backend.models.user import User
    try:
        accessible_ids = set(PermissionService.list_accessible_document_ids(db, int(owner_id)))
        actor = db.query(User).filter(User.id == int(owner_id)).first()
        if not actor:
            return []
        visible_ids = set()
        for doc_id in accessible_ids:
            candidate = db.query(DocumentModel).filter(DocumentModel.id == doc_id, DocumentModel.is_deleted == 0).first()
            if not candidate:
                continue
            candidate_token = PermissionService.resolve_access_lock_token(
                db, actor, candidate, lock_tokens=lock_tokens,
                fallback_token=lock_token if int(candidate.id) == int(target_doc.id) else None,
            )
            if PermissionService.check_access_lock(db, actor, candidate, candidate_token):
                visible_ids.add(doc_id)
        accessible_ids = visible_ids
    except Exception:
        return []
    if int(target_doc.id) not in accessible_ids:
        return []
    candidate_ids = _duplicate_p0_03_discover_candidate_ids(
        self, db, target_doc, owner_id
    )

    repo = DocumentRepository(db)
    filtered = []

    for cand_id in candidate_ids:
        cand_doc = repo.get_by_id(cand_id)
        if not cand_doc or cand_doc.id not in accessible_ids or cand_doc.is_deleted:
            continue
        try:
            eb = _duplicate_v11_reclassify(
                _DUPLICATE_V11_ORIGINAL_EVALUATE_PAIR(self, target_doc, cand_doc)
            )
        except Exception:
            continue

        same_owner_pair = (int(target_doc.owner_id) == int(owner_id) and int(cand_doc.owner_id) == int(owner_id))
        if not is_actionable_duplicate(eb.scores or {}):
            # Owner-library relations can be marked stale; a recipient analysis must not
            # mutate shared/cross-owner global relationship history.
            if same_owner_pair:
                try:
                    repo.mark_duplicate_relation_stale(target_doc.id, cand_doc.id)
                except Exception:
                    pass
            continue

        filtered.append(eb)
        if same_owner_pair:
            try:
                repo.upsert_duplicate_relation(
                    doc_a_id=target_doc.id,
                    doc_b_id=cand_doc.id,
                    relation_type=eb.relation_type,
                    score=eb.confidence,
                    detected_by=", ".join(eb.detection_methods)
                    if eb.detection_methods else "system",
                )
            except Exception:
                pass

    filtered.sort(key=lambda x: x.confidence, reverse=True)
    return filtered


DuplicateService.evaluate_pair = _duplicate_v11_evaluate_pair
DuplicateService.analyze_all_candidates = _duplicate_v11_analyze_all_candidates
# --- END DUPLICATE_POLICY_V11_20261008_SERVICE ----------------------------



# INTELLIDOCS_V19_PERSISTENT_SUGGESTIONS_DUPLICATE_REPAIR


# INTELLIDOCS_RECEIVER_SHARED_DUPLICATE_SCOPE_V1
