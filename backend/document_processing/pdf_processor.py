from pathlib import Path
from PIL import Image
import fitz  # PyMuPDF
from backend.document_processing.base_processor import DocumentProcessor, ProcessedContent, compute_text_quality
from backend.utils.perceptual_hash import compute_dhash, compute_pdf_page_dhashes

class PDFProcessor(DocumentProcessor):
    def extract(self, file_path: Path) -> ProcessedContent:
        doc = fitz.open(str(file_path))
        text_parts = []
        has_embedded_js = False

        page_count = len(doc)
        metadata = {
            "title": doc.metadata.get("title", ""),
            "author": doc.metadata.get("author", ""),
            "subject": doc.metadata.get("subject", ""),
            "creation_date": doc.metadata.get("creationDate", ""),
            "producer": doc.metadata.get("producer", "")
        }

        for i, page in enumerate(doc):
            text = page.get_text("text")
            if text:
                text_parts.append(text)
            
            page_text_raw = page.get_text("rawdict")
            if "javascript" in str(page_text_raw).lower():
                has_embedded_js = True

        full_text = "\n".join(text_parts).strip()
        word_count = len(full_text.split()) if full_text else 0
        text_quality = compute_text_quality(full_text, word_count)

        has_ocr = False
        ocr_confidence = None

        # OCR fallback if native text extraction is sparse/insufficient
        if text_quality < 0.40 or word_count < 20:
            ocr_texts = []
            try:
                import pytesseract
                for i in range(min(page_count, 3)):  # Run OCR on first 3 pages
                    page = doc[i]
                    pix = page.get_pixmap(dpi=150)
                    img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                    ocr_part = pytesseract.image_to_string(img).strip()
                    if ocr_part:
                        ocr_texts.append(ocr_part)
                if ocr_texts:
                    ocr_full = "\n".join(ocr_texts).strip()
                    if len(ocr_full) > len(full_text):
                        full_text = ocr_full
                        word_count = len(full_text.split())
                        text_quality = compute_text_quality(full_text, word_count)
                        has_ocr = True
                        ocr_confidence = 0.85
            except Exception:
                pass

        # Compute per-page perceptual dHashes for visual similarity comparison
        doc.close()
        page_hashes = compute_pdf_page_dhashes(file_path, max_pages=5)
        primary_hash = page_hashes[0] if page_hashes else ""

        # Language detection if text exists
        lang = "en"
        if full_text:
            try:
                import langdetect
                lang = langdetect.detect(full_text[:1000])
            except Exception:
                lang = "en"

        return ProcessedContent(
            text=full_text,
            page_count=page_count,
            word_count=word_count,
            language=lang,
            metadata=metadata,
            has_ocr=has_ocr,
            ocr_confidence=ocr_confidence,
            has_embedded_js=has_embedded_js,
            perceptual_hash=primary_hash,
            page_hashes=page_hashes,
            text_quality_score=text_quality
        )

    def generate_thumbnail(self, file_path: Path, out_path: Path) -> bool:
        try:
            doc = fitz.open(str(file_path))
            if len(doc) > 0:
                page = doc[0]
                pix = page.get_pixmap(dpi=150)
                pix.save(str(out_path))
                doc.close()
                return True
            doc.close()
        except Exception:
            pass
        return False
