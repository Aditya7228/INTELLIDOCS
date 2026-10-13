import os
from pathlib import Path
import numpy as np
from backend.config import settings

class EmbeddingEngine:
    """
    Sentence Transformers wrapper for local dense text embeddings (all-MiniLM-L6-v2).
    """
    _model = None
    _available = False

    def __init__(self):
        if settings.ENABLE_SEMANTIC_SEARCH:
            self._load_model()

    def _load_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            # Load local model or cache
            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._available = True
        except Exception:
            self._available = False
            self._model = None

    def is_available(self) -> bool:
        return self._available and self._model is not None

    def encode(self, text: str) -> np.ndarray:
        if not self.is_available() or not text:
            return np.zeros(384, dtype=np.float32)
        try:
            embedding = self._model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
            return embedding.astype(np.float32)
        except Exception:
            return np.zeros(384, dtype=np.float32)

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        if not self.is_available() or not texts:
            return np.zeros((len(texts), 384), dtype=np.float32)
        try:
            embeddings = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            return embeddings.astype(np.float32)
        except Exception:
            return np.zeros((len(texts), 384), dtype=np.float32)
