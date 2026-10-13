import os
import uuid
import shutil
from pathlib import Path
from typing import Tuple
from backend.security.path_guard import PathGuard
from backend.config import settings

class QuarantineManager:
    """
    Manages isolated temporary quarantine storage for untrusted uploads.
    Prevents unverified files from entering permanent library storage (storage/uploads/).
    """

    def __init__(self):
        self.path_guard = PathGuard()
        self.quarantine_dir = Path(settings.STORAGE_DIR) / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def save_to_quarantine(self, file_bytes: bytes, filename: str) -> Tuple[str, str, Path]:
        """
        Saves incoming untrusted upload into isolated quarantine.
        Returns (quarantine_uuid, stored_quarantine_name, absolute_path).
        """
        quarantine_uuid = str(uuid.uuid4())
        _, ext = os.path.splitext(filename)
        safe_ext = ext.lower().replace(" ", "") or ".tmp"
        stored_quarantine_name = f"{quarantine_uuid}{safe_ext}"
        
        target_path = self.quarantine_dir / stored_quarantine_name
        with open(target_path, "wb") as f:
            f.write(file_bytes)
            
        return quarantine_uuid, stored_quarantine_name, target_path

    def get_quarantine_path(self, stored_quarantine_name: str) -> Path:
        """Returns verified safe path within quarantine directory."""
        path = self.quarantine_dir / stored_quarantine_name
        if not path.is_relative_to(self.quarantine_dir):
            raise ValueError("Path traversal attempt in quarantine manager")
        return path

    def delete_quarantined_file(self, stored_quarantine_name: str) -> bool:
        """Safely removes file from quarantine."""
        try:
            path = self.get_quarantine_path(stored_quarantine_name)
            if path.exists():
                os.remove(path)
                return True
        except Exception:
            pass
        return False

    def promote_to_uploads(self, stored_quarantine_name: str, target_name: str) -> Path:
        """
        Moves cleared file from storage/quarantine/ to storage/uploads/.
        Only invoked when security assessment verdict is SAFE (or cleared).
        """
        q_path = self.get_quarantine_path(stored_quarantine_name)
        if not q_path.exists():
            raise FileNotFoundError(f"Quarantined file {stored_quarantine_name} not found")

        dest_path = self.path_guard.safe_upload_path(target_name)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(q_path), str(dest_path))
        return dest_path
