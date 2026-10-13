import os
from pathlib import Path
from backend.config import settings

class SecurityError(Exception):
    pass

class PathGuard:
    def __init__(self, storage_root: Path = None):
        self.storage_root = (storage_root or Path(settings.STORAGE_DIR)).resolve()

    def safe_upload_path(self, stored_name: str) -> Path:
        uploads_dir = self.storage_root / "uploads"
        candidate = (uploads_dir / stored_name).resolve()
        self._verify_bounds(candidate, uploads_dir)
        return candidate

    def safe_thumbnail_path(self, stored_name: str) -> Path:
        thumbnails_dir = self.storage_root / "thumbnails"
        candidate = (thumbnails_dir / stored_name).resolve()
        self._verify_bounds(candidate, thumbnails_dir)
        return candidate

    def safe_file_path(self, relative_path: str) -> Path:
        candidate = (self.storage_root / relative_path).resolve()
        self._verify_bounds(candidate, self.storage_root)
        return candidate

    def _verify_bounds(self, candidate: Path, allowed_dir: Path):
        allowed_dir = allowed_dir.resolve()
        candidate = candidate.resolve()

        # Component-aware containment check prevents sibling-prefix bypasses.
        if not candidate.is_relative_to(allowed_dir):
            raise SecurityError("Path traversal attack detected!")
