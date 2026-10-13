from pathlib import Path
from PIL import Image
from backend.document_processing.base_processor import DocumentProcessor, ProcessedContent, compute_text_quality
from backend.utils.perceptual_hash import compute_dhash
# === IntelliDocs V17 local visual understanding ===
# Captioning is local-only. Model weights are downloaded once by the V17 setup
# runner; request-time image inference never contacts a remote service.
import logging as _id_v17_logging
import os as _id_v17_os
import threading as _id_v17_threading

_ID_V17_LOG = _id_v17_logging.getLogger(__name__)
_ID_V17_MODEL_ID = _id_v17_os.environ.get(
    "INTELLIDOCS_IMAGE_CAPTION_MODEL", "Salesforce/blip-image-captioning-base"
)
_ID_V17_MODEL = None
_ID_V17_PROCESSOR = None
_ID_V17_LOAD_ATTEMPTED = False
_ID_V17_LOAD_LOCK = _id_v17_threading.Lock()
_ID_V17_INFERENCE_LOCK = _id_v17_threading.Lock()
_ID_V17_GENERIC_CAPTIONS = {
    "a document with text on it", "a piece of paper with writing on it",
    "a page of text", "a sheet of paper with text on it", "a document",
    "a picture of a document", "a screenshot of a computer screen",
    "a close up of a piece of paper", "a white piece of paper",
}


def _id_v17_useful_caption(value):
    value = " ".join(str(value or "").replace("\x00", " ").split()).strip(" .,:;-")
    normalized = value.lower()
    if not value or len(value) < 8 or len(value) > 240:
        return ""
    if normalized in _ID_V17_GENERIC_CAPTIONS:
        return ""
    # Reject non-descriptive fragments, but permit short object descriptions.
    words = normalized.split()
    if len(words) < 3 or not any(ch.isalpha() for ch in value):
        return ""
    return value[:240]


def _id_v17_load_caption_model():
    """Load BLIP from the local Hugging Face cache only; never download at upload time."""
    global _ID_V17_MODEL, _ID_V17_PROCESSOR, _ID_V17_LOAD_ATTEMPTED
    enabled = _id_v17_os.environ.get("INTELLIDOCS_IMAGE_CAPTIONING", "1").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return None, None
    if _ID_V17_LOAD_ATTEMPTED:
        return _ID_V17_PROCESSOR, _ID_V17_MODEL
    with _ID_V17_LOAD_LOCK:
        if _ID_V17_LOAD_ATTEMPTED:
            return _ID_V17_PROCESSOR, _ID_V17_MODEL
        _ID_V17_LOAD_ATTEMPTED = True
        try:
            from transformers import BlipForConditionalGeneration, BlipProcessor
            processor = BlipProcessor.from_pretrained(_ID_V17_MODEL_ID, local_files_only=True)
            model = BlipForConditionalGeneration.from_pretrained(_ID_V17_MODEL_ID, local_files_only=True)
            model.to("cpu")
            model.eval()
            _ID_V17_PROCESSOR, _ID_V17_MODEL = processor, model
            _ID_V17_LOG.info("IntelliDocs local image caption model loaded: %s", _ID_V17_MODEL_ID)
        except Exception as exc:
            _ID_V17_PROCESSOR = None
            _ID_V17_MODEL = None
            _ID_V17_LOG.warning(
                "Local image caption model unavailable; OCR-only fallback will be used. "
                "Run the IntelliDocs V17 setup runner with image-model download enabled. (%s)",
                type(exc).__name__,
            )
    return _ID_V17_PROCESSOR, _ID_V17_MODEL


def _id_v17_caption_image(image):
    processor, model = _id_v17_load_caption_model()
    if processor is None or model is None:
        return ""
    try:
        import torch
        rgb = image.convert("RGB")
        inputs = processor(images=rgb, return_tensors="pt")
        with _ID_V17_INFERENCE_LOCK, torch.inference_mode():
            output = model.generate(**inputs, max_new_tokens=40, num_beams=3)
        caption = processor.decode(output[0], skip_special_tokens=True)
        return _id_v17_useful_caption(caption)
    except Exception as exc:
        _ID_V17_LOG.warning("Local image caption generation failed (%s)", type(exc).__name__)
        return ""

# === End IntelliDocs V17 local visual understanding ===

class ImageProcessor(DocumentProcessor):
    def extract(self, file_path: Path) -> ProcessedContent:
        img = Image.open(str(file_path))
        width, height = img.size
        metadata = {
            "width": width,
            "height": height,
            "format": img.format or "",
            "mode": img.mode or ""
        }

        # Calculate perceptual dHash for image
        primary_hash = compute_dhash(img)

        ocr_text = ""
        has_ocr = False
        confidence = None

        # OCR extracts readable words from scanned documents and screenshots.
        try:
            import pytesseract
            ocr_text = pytesseract.image_to_string(img).strip()
            if ocr_text:
                has_ocr = True
                confidence = 0.85
        except Exception as exc:
            # OCR being unavailable must not prevent visual understanding.
            _ID_V17_LOG.debug("Local OCR unavailable for image (%s)", type(exc).__name__)

        # BLIP adds a local visual description for photos/screenshots/graphics,
        # including images with little or no readable text. OCR is still retained.
        visual_description = _id_v17_caption_image(img)
        metadata["visual_description"] = visual_description
        metadata["visual_understanding"] = (
            "ocr_and_local_caption" if has_ocr and visual_description
            else "ocr" if has_ocr
            else "local_caption" if visual_description
            else "ocr_only_fallback"
        )

        # If OCR is sparse, put the image description first so downstream
        # summarization, category inference, smart naming and foldering can use it.
        ocr_words = len([w for w in ocr_text.split() if any(c.isalpha() for c in w)])
        if visual_description and ocr_words < 6:
            pieces = [visual_description, ocr_text]
        else:
            pieces = [ocr_text, visual_description]
        full_text = "\n".join(piece.strip() for piece in pieces if piece and piece.strip()).strip()
        if not full_text:
            full_text = f"[Image document: {file_path.name} ({width}x{height})]"

        word_count = len(full_text.split()) if full_text else 0
        text_quality = compute_text_quality(full_text, word_count)

        return ProcessedContent(
            text=full_text,
            page_count=1,
            word_count=word_count,
            language="en",
            metadata=metadata,
            has_ocr=has_ocr,
            ocr_confidence=confidence,
            perceptual_hash=primary_hash,
            page_hashes=[primary_hash] if primary_hash else [],
            text_quality_score=text_quality
        )

    def generate_thumbnail(self, file_path: Path, out_path: Path) -> bool:
        try:
            img = Image.open(str(file_path))
            img.thumbnail((300, 300))
            img.save(str(out_path))
            return True
        except Exception:
            return False
