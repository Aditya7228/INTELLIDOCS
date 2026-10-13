import re
import hashlib
from typing import Set, List, Dict, Tuple

class MinHashLSH:
    """
    MinHash & Locality-Sensitive Hashing (LSH) technique for near-duplicate candidate detection.
    - Shingles text into 3-character shingles
    - Computes 128 MinHash signature permutations
    - Bands signature into 16 bands x 8 rows
    - Hashes bands into LSH bucket keys
    """
    def __init__(self, num_perm: int = 128, num_bands: int = 16):
        self.num_perm = num_perm
        self.num_bands = num_bands
        self.rows_per_band = num_perm // num_bands  # 8
        self._buckets: Dict[Tuple[int, str], List[int]] = {}  # (band_idx, bucket_hash) -> [doc_ids]
        self._signatures: Dict[int, List[int]] = {}           # doc_id -> signature
        self._a = [(i * 2654435761 + 1013904223) & 0xFFFFFFFF for i in range(1, num_perm + 1)]
        self._b = [(i * 1103515245 + 12345) & 0xFFFFFFFF for i in range(1, num_perm + 1)]
        self._prime = 4294967311  # large prime > 2^32

    @staticmethod
    def get_shingles(text: str, k: int = 3) -> Set[str]:
        cleaned = re.sub(r"\s+", " ", text.lower().strip())
        if len(cleaned) < k:
            return {cleaned} if cleaned else set()
        return {cleaned[i:i+k] for i in range(len(cleaned) - k + 1)}

    def compute_signature(self, shingles: Set[str]) -> List[int]:
        if not shingles:
            return [0] * self.num_perm

        sig = []
        # Convert shingle strings to integer hashes
        shingle_hashes = [int(hashlib.md5(s.encode("utf-8")).hexdigest()[:8], 16) for s in shingles]

        for i in range(self.num_perm):
            a, b = self._a[i], self._b[i]
            min_val = min((a * h + b) % self._prime for h in shingle_hashes)
            sig.append(min_val)
        return sig

    def add(self, doc_id: int, text: str) -> List[int]:
        shingles = self.get_shingles(text)
        sig = self.compute_signature(shingles)
        self._signatures[doc_id] = sig

        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band_portion = tuple(sig[start:end])
            bucket_hash = hashlib.md5(str(band_portion).encode("utf-8")).hexdigest()
            key = (band_idx, bucket_hash)

            if key not in self._buckets:
                self._buckets[key] = []
            if doc_id not in self._buckets[key]:
                self._buckets[key].append(doc_id)

        return sig

    def query_candidates(self, text: str) -> Set[int]:
        shingles = self.get_shingles(text)
        sig = self.compute_signature(shingles)
        candidates = set()

        for band_idx in range(self.num_bands):
            start = band_idx * self.rows_per_band
            end = start + self.rows_per_band
            band_portion = tuple(sig[start:end])
            bucket_hash = hashlib.md5(str(band_portion).encode("utf-8")).hexdigest()
            key = (band_idx, bucket_hash)

            if key in self._buckets:
                candidates.update(self._buckets[key])

        return candidates

    def jaccard_similarity(self, sig1: List[int], sig2: List[int]) -> float:
        if not sig1 or not sig2 or len(sig1) != len(sig2):
            return 0.0
        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)

    def remove(self, doc_id: int):
        self._signatures.pop(doc_id, None)
        for key, doc_list in list(self._buckets.items()):
            if doc_id in doc_list:
                doc_list.remove(doc_id)
                if not doc_list:
                    del self._buckets[key]
