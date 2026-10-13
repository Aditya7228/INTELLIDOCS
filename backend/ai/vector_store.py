from pathlib import Path
import numpy as np
from typing import List, Tuple, Dict
from backend.config import settings

class VectorStore:
    """
    FAISS-cpu vector store for dense vector ANN search.
    """
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.index = None
        self._doc_id_to_faiss: Dict[int, int] = {}
        self._faiss_to_doc_id: Dict[int, int] = {}
        self._available = False
        self._init_faiss()

    def _init_faiss(self):
        try:
            import faiss
            self.index = faiss.IndexFlatIP(self.dimension)  # Inner Product (Cosine similarity on normalized vectors)
            self._available = True
        except Exception:
            self._available = False
            self.index = None

    def is_available(self) -> bool:
        return self._available and self.index is not None

    # INTELLIDOCS_VECTOR_STORE_RESET_V1
    def reset(self):
        """Clear FAISS vectors and both document-ID mappings."""
        self._doc_id_to_faiss.clear()
        self._faiss_to_doc_id.clear()
        if not self._available:
            self.index = None
            return
        try:
            import faiss
            self.index = faiss.IndexFlatIP(self.dimension)
        except Exception:
            self.index = None
            self._available = False
            raise

    def add(self, doc_id: int, vector: np.ndarray):
        if not self.is_available() or vector is None:
            return
        if vector.ndim == 1:
            vector = np.expand_dims(vector, axis=0)

        faiss_id = self.index.ntotal
        self.index.add(vector)
        self._doc_id_to_faiss[doc_id] = faiss_id
        self._faiss_to_doc_id[faiss_id] = doc_id

    def search(self, query_vector: np.ndarray, top_k: int = 10) -> List[Tuple[int, float]]:
        if not self.is_available() or self.index.ntotal == 0:
            return []
        if query_vector.ndim == 1:
            query_vector = np.expand_dims(query_vector, axis=0)

        k = min(top_k, self.index.ntotal)
        scores, faiss_ids = self.index.search(query_vector, k)

        results = []
        for score, f_id in zip(scores[0], faiss_ids[0]):
            if f_id in self._faiss_to_doc_id:
                doc_id = self._faiss_to_doc_id[f_id]
                results.append((doc_id, float(score)))

        return results

    def save(self, path: Path):
        if not self.is_available() or self.index is None:
            return
        try:
            import faiss
            faiss.write_index(self.index, str(path / "faiss.index"))
        except Exception:
            pass

    def load(self, path: Path):
        if not self.is_available():
            return
        try:
            import faiss
            index_file = path / "faiss.index"
            if index_file.exists():
                self.index = faiss.read_index(str(index_file))
        except Exception:
            pass
