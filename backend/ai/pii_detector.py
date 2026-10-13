import re
from typing import Tuple, List, Optional

# Regex patterns for PII detection (always work offline)
REGEX_PATTERNS = {
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "PHONE_IN": r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
    "AADHAAR": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
    "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "BANK_ACCOUNT": r"(?i)\b(?:bank\s*(?:account|a/c)|account\s*(?:number|no|#))\s*[:#-]?\s*\d{8,18}\b"
}

class PIIDetector:
    """
    Sensitivity/PII detection service.
    - Rule-based regex detection always works offline.
    - Optional spaCy NER model runs if available.
    """
    def __init__(self):
        self._nlp = None
        self._spacy_available = False
        self._init_spacy()

    def _init_spacy(self):
        try:
            import spacy
            self._nlp = spacy.load("en_core_web_sm")
            self._spacy_available = True
        except Exception:
            self._spacy_available = False
            self._nlp = None

    def detect_pii(self, text: str) -> Tuple[str, List[str]]:
        """
        Returns (sensitivity_level, found_types).
        sensitivity_level: 'public', 'internal', or 'pii'
        """
        if not text:
            return "public", []

        found_types = set()

        # 1. Regex rule-based detection
        for pii_type, pattern in REGEX_PATTERNS.items():
            if re.search(pattern, text):
                found_types.add(pii_type)

        # 2. spaCy NER enhancement if available
        if self._spacy_available and self._nlp is not None:
            try:
                doc = self._nlp(text[:2000])  # limit sample size for performance
                for ent in doc.ents:
                    if ent.label_ in ("PERSON", "ORG", "DATE", "GPE", "CARDINAL"):
                        found_types.add(f"NER_{ent.label_}")
            except Exception:
                pass

        if (
            "EMAIL" in found_types
            or "AADHAAR" in found_types
            or "PAN" in found_types
            or "CREDIT_CARD" in found_types
            or "SSN" in found_types
            or "BANK_ACCOUNT" in found_types
        ):
            return "pii", list(found_types)
        elif "PHONE_IN" in found_types or any(t.startswith("NER_PERSON") for t in found_types):
            return "pii", list(found_types)
        elif len(found_types) > 0:
            return "internal", list(found_types)

        return "public", []
