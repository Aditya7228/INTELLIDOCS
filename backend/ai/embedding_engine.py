import os
from pathlib import Path
import threading
import numpy as np
from backend.config import settings

class EmbeddingEngine:
    """
    Sentence Transformers wrapper for local dense text embeddings (all-MiniLM-L6-v2).
    """
    _model = None
    _available = False

    def __init__(self):
        # Defer heavy model loading until after the web server binds its port.
        self._model = None
        self._available = False
        self._load_attempted = False
        self._load_lock = threading.Lock()

    def ensure_loaded(self) -> bool:
        if not settings.ENABLE_SEMANTIC_SEARCH:
            return False
        if self.is_available():
            return True
        with self._load_lock:
            if self.is_available():
                return True
            if self._load_attempted:
                return False
            self._load_attempted = True
            self._load_model()
        return self.is_available()

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
        if not self.is_available():
            self.ensure_loaded()
        if not self.is_available() or not text:
            return np.zeros(384, dtype=np.float32)
        try:
            embedding = self._model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
            return embedding.astype(np.float32)
        except Exception:
            return np.zeros(384, dtype=np.float32)

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        if not self.is_available():
            self.ensure_loaded()
        if not self.is_available() or not texts:
            return np.zeros((len(texts), 384), dtype=np.float32)
        try:
            embeddings = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            return embeddings.astype(np.float32)
        except Exception:
            return np.zeros((len(texts), 384), dtype=np.float32)
