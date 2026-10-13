"""Regression tests for startup rebuilding of keyword/autocomplete indexes."""
from types import SimpleNamespace

from backend.algorithms.graph import DocumentGraph
from backend.algorithms.inverted_index import InvertedIndex
from backend.algorithms.trie import Trie
from backend.core.search_service import SearchService
from backend.models.document import DocumentModel


class FakeQuery:
    def __init__(self, docs):
        self.docs = docs
        self.filter_expressions = []

    def filter(self, expression):
        self.filter_expressions.append(expression)
        return self

    def order_by(self, expression):
        return self

    def all(self):
        return list(self.docs)


class FakeDB:
    def __init__(self, docs):
        self.docs = docs
        self.queried_model = None
        self.query_obj = FakeQuery(docs)

    def query(self, model):
        self.queried_model = model
        return self.query_obj


def _service():
    return SearchService(InvertedIndex(), Trie(), DocumentGraph())


def _doc(doc_id, text):
    return SimpleNamespace(id=doc_id, is_deleted=0, owner_id=1, extracted_text=text)


def test_rebuild_uses_document_model_and_restores_keyword_and_autocomplete():
    docs = [_doc(11, "alpha alpha restartable term"), _doc(22, "beta searchable phrase")]
    db = FakeDB(docs)
    service = _service()

    count = service.rebuild_index(db)

    assert db.queried_model is DocumentModel
    assert count == 2
    keyword_hits = service.inverted_index.search("alpha")
    assert keyword_hits and keyword_hits[0][0] == 11
    assert "restartable" in service.autocomplete("rest", accessible_document_ids={11})
    assert service.autocomplete("rest", accessible_document_ids={22}) == []
    assert 11 in service.document_graph._adj
    assert 22 in service.document_graph._adj


def test_rebuild_is_idempotent_and_cleans_stale_graph_nodes():
    service = _service()
    service.document_graph.add_node(999)
    docs = [_doc(11, "alpha alpha restartable")]
    db = FakeDB(docs)

    service.rebuild_index(db)
    service.rebuild_index(db)

    assert 999 not in service.document_graph._adj
    assert service.inverted_index._total_docs == 1
    assert service.inverted_index._index["alpha"].get_tf(11) == 2
    assert "restartable" in service.autocomplete("rest", accessible_document_ids={11})
