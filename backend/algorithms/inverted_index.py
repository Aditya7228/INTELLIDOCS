import re
import math
from typing import Dict, List, Tuple, Set

class PostingList:
    def __init__(self):
        self._frequencies: Dict[int, int] = {}  # doc_id -> term frequency

    def add(self, doc_id: int):
        self._frequencies[doc_id] = self._frequencies.get(doc_id, 0) + 1

    def remove(self, doc_id: int):
        self._frequencies.pop(doc_id, None)

    def get_tf(self, doc_id: int) -> int:
        return self._frequencies.get(doc_id, 0)

    def get_doc_ids(self) -> Set[int]:
        return set(self._frequencies.keys())

class InvertedIndex:
    """
    Inverted Index data structure mapping token -> posting list (doc_ids with frequencies),
    supporting TF-IDF ranking for keyword search.
    """
    def __init__(self):
        self._index: Dict[str, PostingList] = {}
        self._doc_lengths: Dict[int, int] = {}  # doc_id -> total tokens
        self._total_docs: int = 0

    @staticmethod
    def tokenize(text: str) -> List[str]:
        if not text:
            return []
        cleaned = re.sub(r"[^\w\s]", " ", text.lower())
        tokens = [t for t in cleaned.split() if len(t) > 1]
        return tokens

    def index_document(self, doc_id: int, text: str):
        tokens = self.tokenize(text)
        self._doc_lengths[doc_id] = len(tokens)
        self._total_docs = len(self._doc_lengths)

        for token in tokens:
            if token not in self._index:
                self._index[token] = PostingList()
            self._index[token].add(doc_id)

    def remove_document(self, doc_id: int):
        if doc_id in self._doc_lengths:
            del self._doc_lengths[doc_id]
            self._total_docs = len(self._doc_lengths)

        for posting_list in self._index.values():
            posting_list.remove(doc_id)

    def search(self, query: str) -> List[Tuple[int, float]]:
        tokens = self.tokenize(query)
        if not tokens:
            return []

        doc_scores: Dict[int, float] = {}

        for token in set(tokens):
            if token in self._index:
                posting_list = self._index[token]
                doc_ids = posting_list.get_doc_ids()
                df = len(doc_ids)
                if df == 0 or self._total_docs == 0:
                    continue

                # Inverse Document Frequency (IDF)
                idf = math.log((self._total_docs + 1) / (df + 1)) + 1.0

                for doc_id in doc_ids:
                    tf = posting_list.get_tf(doc_id)
                    doc_len = self._doc_lengths.get(doc_id, 1)
                    normalized_tf = tf / max(doc_len, 1)
                    score = normalized_tf * idf
                    doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + score

        # Sort by TF-IDF score descending
        sorted_results = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_results
