"""Regression tests for rebuilding semantic FAISS vectors from persisted text."""
from pathlib import Path
from types import SimpleNamespace
import numpy as np

from backend.models.document import DocumentModel
from backend.core.vector_index_recovery import rebuild_vector_index


class FakeQuery:
    def __init__(self, docs):
        self.docs = docs
        self.filters = []
        self.order = None
        self.batch_size = None

    def filter(self, *expressions):
        self.filters.extend(expressions)
        return self

    def order_by(self, expression):
        self.order = expression
        return self

    def yield_per(self, batch_size):
        self.batch_size = batch_size
        # Stand-in for the database returning active rows selected by the query.
        return iter(self.docs)


class FakeDB:
    def __init__(self, docs):
        self.docs = docs
        self.queried_model = None
        self.query_obj = FakeQuery(docs)

    def query(self, model):
        self.queried_model = model
        return self.query_obj


class FakeEmbeddingEngine:
    def __init__(self, available=True):
        self.available = available
        self.batch_sizes = []

    def is_available(self):
        return self.available

    def encode_batch(self, texts):
        self.batch_sizes.append(len(texts))
        result = np.zeros((len(texts), 4), dtype=np.float32)
        for index, text in enumerate(texts):
            if text.strip() and not text.startswith("zero-vector"):
                result[index, index % 4] = 1.0
        return result


class FakeVectorStore:
    dimension = 4

    def __init__(self, available=True):
        self.available = available
        self.entries = {}
        self.reset_count = 0

    def is_available(self):
        return self.available

    def reset(self):
        self.reset_count += 1
        self.entries.clear()

    def add(self, doc_id, vector):
        self.entries[doc_id] = np.array(vector, dtype=np.float32)


def _doc(doc_id, text, is_deleted=0):
    return SimpleNamespace(id=doc_id, extracted_text=text, is_deleted=is_deleted)


def test_rebuild_restores_doc_id_mappings_from_active_text_in_batches():
    docs = [
        _doc(2, "old invoice contents"),
        _doc(5, "meeting notes contents"),
        _doc(7, "   "),
        _doc(8, "zero-vector intentional test"),
    ]
    db = FakeDB(docs)
    engine = FakeEmbeddingEngine()
    store = FakeVectorStore()

    inserted = rebuild_vector_index(db, engine, store, batch_size=2)

    assert db.queried_model is DocumentModel
    assert {expr.left.key for expr in db.query_obj.filters} >= {"is_deleted", "extracted_text"}
    assert inserted == 2
    assert set(store.entries) == {2, 5}
    assert engine.batch_sizes == [2, 2]
    assert store.reset_count == 1


def test_rebuild_is_idempotent_and_removes_stale_vector_ids():
    db = FakeDB([_doc(3, "persisted document text")])
    engine = FakeEmbeddingEngine()
    store = FakeVectorStore()
    store.entries[999] = np.ones(4, dtype=np.float32)

    assert rebuild_vector_index(db, engine, store) == 1
    assert set(store.entries) == {3}
    assert rebuild_vector_index(db, engine, store) == 1
    assert set(store.entries) == {3}
    assert store.reset_count == 2


def test_unavailable_semantic_components_leave_existing_store_untouched():
    db = FakeDB([_doc(3, "persisted document text")])
    engine = FakeEmbeddingEngine(available=False)
    store = FakeVectorStore()
    store.entries[123] = np.ones(4, dtype=np.float32)

    assert rebuild_vector_index(db, engine, store) == 0
    assert set(store.entries) == {123}
    assert store.reset_count == 0


def test_startup_lifespan_wires_semantic_recovery_without_importing_app():
    source = Path("backend/main.py").read_text(encoding="utf-8-sig")
    assert "INTELLIDOCS_STARTUP_VECTOR_INDEX_RECOVERY_V1" in source
    assert "rebuild_vector_index(" in source
    assert "vector_store.reset()" in source
