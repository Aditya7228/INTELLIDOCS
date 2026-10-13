from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List

@dataclass
class ProcessedContent:
    text: str
    page_count: int = 1
    word_count: int = 0
    language: str = "en"
    metadata: Dict[str, Any] = field(default_factory=dict)
    has_ocr: bool = False
    ocr_confidence: Optional[float] = None
    has_embedded_js: bool = False
    perceptual_hash: Optional[str] = None
    page_hashes: List[str] = field(default_factory=list)
    text_quality_score: float = 1.0

def compute_text_quality(text: str, word_count: int) -> float:
    """
    Calculate composite TextQualityScore (0.0 to 1.0).
    Scores lower when text contains non-printable noise or sparse words.
    """
    if not text:
        return 0.0
    total_chars = len(text)
    if total_chars == 0:
        return 0.0
    alpha_chars = sum(1 for c in text if c.isalnum() or c.isspace())
    char_quality = alpha_chars / total_chars
    word_factor = min(1.0, word_count / 30.0)
    return round(char_quality * word_factor, 4)

class DocumentProcessor(ABC):
    @abstractmethod
    def extract(self, file_path: Path) -> ProcessedContent:
        pass

    def generate_thumbnail(self, file_path: Path, out_path: Path) -> bool:
        return False

    @staticmethod
    def for_mime_type(mime_type: str) -> "DocumentProcessor":
        from backend.document_processing.pdf_processor import PDFProcessor
        from backend.document_processing.docx_processor import DOCXProcessor
        from backend.document_processing.image_processor import ImageProcessor

        if mime_type == "application/pdf":
            return PDFProcessor()
        elif mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return DOCXProcessor()
        elif mime_type in ("image/png", "image/jpeg", "image/tiff"):
            return ImageProcessor()
        else:
            raise ValueError(f"No processor registered for MIME type: {mime_type}")
