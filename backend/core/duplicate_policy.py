"""Authoritative duplicate classification policy.

This module intentionally contains only deterministic evidence classification.
Candidate discovery, persistence, UI filtering, and semantic search are outside
this policy boundary.
"""

from dataclasses import dataclass
from typing import Mapping, Any

DUPLICATE_EXACT_THRESHOLD = 0.90
DUPLICATE_NEAR_THRESHOLD = 0.65


@dataclass(frozen=True)
class DuplicateClassification:
    """Final duplicate state derived from strict duplicate evidence."""

    relation_type: str
    confidence: float
    actionable: bool


def strict_duplicate_score(scores: Mapping[str, Any]) -> float:
    """Return the strongest *strict* duplicate evidence.

    Strict duplicate evidence is limited to text/OCR and visual similarity.
    Dense semantic embedding similarity is deliberately excluded because
    semantic relatedness is not proof of duplication.
    """

    text_score = max(
        float(scores.get("normalized_content_sim", 0.0) or 0.0),
        float(scores.get("minhash_lsh_sim", 0.0) or 0.0),
        float(scores.get("ocr_text_sim", 0.0) or 0.0),
    )
    visual_score = float(scores.get("visual_perceptual_sim", 0.0) or 0.0)
    return max(0.0, min(1.0, max(text_score, visual_score)))


def classify_duplicate_evidence(scores: Mapping[str, Any]) -> DuplicateClassification:
    """Classify one measured evidence tuple using the single project policy.

    Policy:
      * SHA-256 match -> exact duplicate (1.0)
      * strict evidence >= 0.90 -> exact duplicate
      * strict evidence >= 0.65 -> near duplicate
      * strict evidence < 0.65 -> related/non-actionable
      * semantic embedding similarity can never independently create a duplicate
    """

    sha_match = float(scores.get("sha256_match", 0.0) or 0.0) > 0.0
    strict_score = strict_duplicate_score(scores)

    if sha_match:
        return DuplicateClassification("exact_duplicate", 1.0, True)

    if strict_score >= DUPLICATE_EXACT_THRESHOLD:
        return DuplicateClassification("exact_duplicate", strict_score, True)

    if strict_score >= DUPLICATE_NEAR_THRESHOLD:
        return DuplicateClassification("near_duplicate", strict_score, True)

    return DuplicateClassification("related", strict_score, False)


def is_actionable_duplicate(scores: Mapping[str, Any]) -> bool:
    """Return whether evidence clears the duplicate-result floor."""

    return classify_duplicate_evidence(scores).actionable


def is_actionable_duplicate_type(relation_type: str, confidence: float) -> bool:
    """Compatibility helper for API layers consuming an already-classified pair."""

    if relation_type == "exact_duplicate":
        return True
    if relation_type == "near_duplicate":
        return float(confidence) >= DUPLICATE_NEAR_THRESHOLD
    return False
