"""Rebuild the process-local FAISS index from persisted extracted document text."""
from __future__ import annotations

from typing import Any
import numpy as np
from backend.models.document import DocumentModel


VECTOR_INDEX_RECOVERY_MARKER = "INTELLIDOCS_VECTOR_INDEX_RECOVERY_V1"


def rebuild_vector_index(
    db: Any,
    embedding_engine: Any,
    vector_store: Any,
    batch_size: int = 32,
) -> int:
    """Re-embed active documents and rebuild FAISS IDs/mappings from database truth.

    This intentionally rebuilds rather than loading only faiss.index, because the
    current on-disk format does not preserve the FAISS-ID-to-document-ID mapping.
    Missing/unavailable ML dependencies are handled by the caller as a degraded
    semantic-search capability; this function returns 0 when either component is
    unavailable.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if not embedding_engine.is_available() or not vector_store.is_available():
        return 0

    query = (
        db.query(DocumentModel)
        .filter(
            DocumentModel.is_deleted == 0,
            DocumentModel.extracted_text.isnot(None),
        )
        .order_by(DocumentModel.id.asc())
    )
    # Clear both the FAISS vectors and both directions of the ID mapping before
    # rebuilding. That makes repeated recovery idempotent and removes stale IDs.
    vector_store.reset()

    inserted = 0
    batch = []

    def flush_batch(items) -> int:
        if not items:
            return 0
        texts = [str(doc.extracted_text or "") for doc in items]
        matrix = np.asarray(embedding_engine.encode_batch(texts), dtype=np.float32)
        if matrix.ndim == 1 and len(items) == 1:
            matrix = matrix.reshape(1, -1)
        if matrix.ndim != 2 or matrix.shape[0] != len(items):
            raise ValueError("Embedding engine returned an unexpected batch shape")

        count = 0
        for doc, vector in zip(items, matrix):
            if getattr(doc, "is_deleted", 0) != 0:
                continue
            if not str(doc.extracted_text or "").strip():
                continue
            vector = np.asarray(vector, dtype=np.float32).reshape(-1)
            if vector.size != int(vector_store.dimension):
                continue
            if not np.isfinite(vector).all() or float(np.linalg.norm(vector)) <= 1e-8:
                # encode_batch returns zero vectors on some model failures; don't
                # pollute ANN results with those vectors.
                continue
            vector_store.add(int(doc.id), vector)
            count += 1
        return count

    for doc in query.yield_per(batch_size):
        batch.append(doc)
        if len(batch) >= batch_size:
            inserted += flush_batch(batch)
            batch = []
    inserted += flush_batch(batch)
    return inserted
