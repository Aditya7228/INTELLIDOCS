from PIL import Image
from pathlib import Path
from typing import List, Optional

def compute_dhash(image: Image.Image, hash_size: int = 8) -> str:
    """
    Calculate 64-bit Difference Hash (dHash) for a PIL Image.
    Fast, robust, O(1) space visual fingerprinting.
    """
    try:
        # Resize image to (hash_size + 1, hash_size) in grayscale
        resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        pixels = list(resized.getdata())

        difference = []
        for row in range(hash_size):
            for col in range(hash_size):
                left = pixels[row * (hash_size + 1) + col]
                right = pixels[row * (hash_size + 1) + col + 1]
                difference.append(left > right)

        # Convert boolean array to hex string
        decimal_val = 0
        for i, val in enumerate(difference):
            if val:
                decimal_val |= 1 << i
        return f"{decimal_val:016x}"
    except Exception:
        return ""

def hamming_distance(hash1: str, hash2: str) -> int:
    """Compute Hamming distance between two 16-character hex dHash strings."""
    if not hash1 or not hash2 or len(hash1) != 16 or len(hash2) != 16:
        return 64
    try:
        val1 = int(hash1, 16)
        val2 = int(hash2, 16)
        xor_val = val1 ^ val2
        return bin(xor_val).count("1")
    except ValueError:
        return 64

def dhash_similarity(hash1: str, hash2: str) -> float:
    """Return similarity score 0.0 - 1.0 from dHash strings."""
    dist = hamming_distance(hash1, hash2)
    return max(0.0, 1.0 - (dist / 64.0))

def compute_pdf_page_dhashes(pdf_path: Path, max_pages: int = 5) -> List[str]:
    """Compute per-page dHashes for up to max_pages of a PDF."""
    hashes = []
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(str(pdf_path))
        num_pages = min(len(doc), max_pages)
        for i in range(num_pages):
            page = doc[i]
            pix = page.get_pixmap(dpi=72)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            h = compute_dhash(img)
            if h:
                hashes.append(h)
        doc.close()
    except Exception:
        pass
    return hashes

def multi_page_visual_similarity(hashes1: List[str], hashes2: List[str]) -> float:
    """
    Compute aggregate visual similarity across page-level dHash lists.
    Compares corresponding page pairs and returns the max/average visual match.
    """
    if not hashes1 or not hashes2:
        return 0.0

    scores = []
    # Compare matching page index pairs
    num_pairs = min(len(hashes1), len(hashes2))
    for i in range(num_pairs):
        sim = dhash_similarity(hashes1[i], hashes2[i])
        scores.append(sim)

    if not scores:
        return 0.0

    return float(sum(scores) / len(scores))
