import os
from dataclasses import dataclass
from backend.config import settings

ALLOWED_MIME_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/tiff": "tiff"
}

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".png", ".jpg", ".jpeg", ".tif", ".tiff"}

@dataclass
class ValidationResult:
    valid: bool
    mime_type: str | None = None
    file_type: str | None = None
    error: str | None = None

class FileValidator:
    # Expose as class attribute so callers can do FileValidator.ALLOWED_MIME_TYPES
    ALLOWED_MIME_TYPES = ALLOWED_MIME_TYPES

    @staticmethod
    def validate_upload(filename: str, content_type: str, file_bytes: bytes) -> ValidationResult:
        # 1. File size check
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        if len(file_bytes) > max_bytes:
            return ValidationResult(valid=False, error=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB")

        if len(file_bytes) == 0:
            return ValidationResult(valid=False, error="File is empty")

        # 2. Extension check
        _, ext = os.path.splitext(filename.lower())
        if ext not in ALLOWED_EXTENSIONS:
            return ValidationResult(valid=False, error=f"Extension '{ext}' is not permitted")

        # 3. Magic bytes inspection
        detected_mime = FileValidator.detect_mime_type(file_bytes, content_type)
        if detected_mime not in ALLOWED_MIME_TYPES:
            return ValidationResult(valid=False, error=f"Unsupported file MIME type: {detected_mime}")

        file_type = ALLOWED_MIME_TYPES[detected_mime]
        if file_type == "png" or file_type == "jpg" or file_type == "tiff":
            file_type = "image"

        return ValidationResult(valid=True, mime_type=detected_mime, file_type=file_type)

    @staticmethod
    def detect_mime_type(header_bytes: bytes, fallback_mime: str) -> str:
        # Magic byte detection logic
        if header_bytes.startswith(b"%PDF"):
            return "application/pdf"
        elif header_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        elif header_bytes.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        elif header_bytes.startswith(b"II*\x00") or header_bytes.startswith(b"MM\x00*"):
            return "image/tiff"
        elif header_bytes.startswith(b"PK\x03\x04"):
            # Zip container check for docx
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

        # Fallback if provided content type matches allowed set
        if fallback_mime in ALLOWED_MIME_TYPES:
            return fallback_mime

        return "application/octet-stream"
