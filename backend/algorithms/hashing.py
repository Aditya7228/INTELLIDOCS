import hashlib
from pathlib import Path

def sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 digest of a byte string."""
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Calculate SHA-256 digest of a file by streaming chunks. O(n) time, O(1) memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()
