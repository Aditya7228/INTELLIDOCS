import re
from typing import Tuple, List, Optional, Dict, Any
from backend.config import settings

# Mapping of common filename abbreviations to expanded search terms
FILENAME_ABBREVIATIONS = {
    "clg": "college",
    "univ": "university",
    "fee": "fees",
    "fees": "fees",
    "rec": "receipt",
    "rcpt": "receipt",
    "assign": "assignment",
    "hw": "homework",
    "cert": "certificate",
    "res": "resume",
    "cv": "curriculum vitae",
    "inv": "invoice",
    "stmt": "statement",
    "rpt": "report",
    "proj": "project",
    "doc": "document",
    "id": "identity",
    "lic": "license",
    "pan": "pan",
    "aadhaar": "aadhaar"
}

CATEGORY_SEMANTIC_PROTOTYPES = {
    "Financial": "financial document invoice receipt fees payment bill tax transaction bank statement salary tuition fees amount due",
    "Academic": "academic college university school syllabus lecture course exam semester student education study",
    "Assignment": "programming assignment homework problem set data structures algorithms lab report submission quiz",
    "Certificate": "certificate certification completion diploma achievement awarded credential course completion",
    "Resume/CV": "resume curriculum vitae work experience skills education career professional profile",
    "Identity": "identity document government identification PAN Aadhaar passport voter ID driver's license identity card",
    "Legal": "legal agreement contract terms conditions NDA policy deed power of attorney legal document",
    "Professional": "professional workplace offer letter experience letter appraisal recommendation corporate work document",
    "Project": "software project report architecture design specification proposal roadmap technical project documentation",
    "Personal": "personal note journal diary family personal file photograph private correspondence",
}


CATEGORY_PATTERNS = {
    "Financial": [r"\binvoices?\b", r"\breceipts?\b", r"\bfees?\b", r"\bpayment\b", r"\bbill\b", r"\btax\b", r"\btransaction\b", r"\bbank statement\b", r"\bamount due\b", r"\bpaid\b", r"\bsalary\b", r"\bpaystub\b", r"\btuition\b"],
    "Academic": [r"\bcollege\b", r"\buniversity\b", r"\bschool\b", r"\bsyllabus\b", r"\blecture\b", r"\bcoursework\b", r"\bexam\b", r"\bacademics?\b", r"\bsemester\b", r"\bstudent\b"],
    "Assignment": [r"\bassignments?\b", r"\bhomework\b", r"\bproblem set\b", r"\bdsa\b", r"\balgorithms?\b", r"\blab report\b", r"\bsubmission\b", r"\bquiz\b"],
    "Certificate": [r"\bcertificates?\b", r"\bcertify\b", r"\bcompletion\b", r"\bawarded\b", r"\bdiploma\b", r"\bachievement\b", r"\bcertification\b"],
    "Resume/CV": [r"\bresumes?\b", r"\bcurriculum vitae\b", r"\bcv\b", r"\bwork experience\b", r"\bskills\b", r"\beducation\b", r"\bcareer\b"],
    "Identity": [r"\bpan\b", r"\baadhaar\b", r"\bpassport\b", r"\bvoter id\b", r"\bdriver['s]* license\b", r"\bid card\b", r"\bidentity\b", r"\bssn\b"],
    "Legal": [r"\bagreements?\b", r"\bcontracts?\b", r"\bterms and conditions\b", r"\bnda\b", r"\bpolicy\b", r"\bdeed\b", r"\bpower of attorney\b"],
    "Professional": [r"\boffer letter\b", r"\bexperience letter\b", r"\bappraisal\b", r"\brecommendation\b", r"\bcorporate\b"],
    "Project": [r"\bproject report\b", r"\barchitecture\b", r"\bdesign doc\b", r"\bspecification\b", r"\bproposal\b"],
    "Personal": [r"\bpersonal\b", r"\bjournal\b", r"\bdiary\b", r"\bfamily\b", r"\bphoto\b"]
}

# Backward compatibility map for legacy tests
RULE_CATEGORIES = {
    "Invoice": CATEGORY_PATTERNS["Financial"],
    "Report": CATEGORY_PATTERNS["Project"],
    "Contract": CATEGORY_PATTERNS["Legal"],
    "Form": [r"\bapplication form\b", r"\bregistration\b", r"\bdeclaration\b", r"\bapplicant\b"],
    "Letter": [r"\bdear\b", r"\bsincerely\b", r"\bregards\b", r"\bto whom it may concern\b"],
    "Receipt": CATEGORY_PATTERNS["Financial"],
    "Certificate": CATEGORY_PATTERNS["Certificate"],
    "Resume": CATEGORY_PATTERNS["Resume/CV"]
}

class DocumentClassifier:
    """
    Multi-signal Document Classifier.
    Reasons from filename + OCR text + file type + PII signals + metadata.
    Operates 100% offline with zero-shot transformer fallback if enabled.
    """
    def __init__(self, embedding_engine=None):
        self.embedding_engine = embedding_engine
        self._zero_shot_pipeline = None
        self._zero_shot_available = False
        self._semantic_prototype_vectors = None
        if settings.ENABLE_ZERO_SHOT_CLASSIFIER:
            self._init_zero_shot()

    def _semantic_scores(self, text: str) -> Dict[str, float]:
        """Return category similarities using the existing local embedding engine.

        This is optional and fails closed: if the local model is unavailable, the
        normal filename/OCR/PII rule signals continue to work without network access.
        """
        engine = self.embedding_engine
        if engine is None or not text.strip():
            return {}
        try:
            if not engine.is_available():
                return {}
            categories = list(CATEGORY_SEMANTIC_PROTOTYPES.keys())
            if self._semantic_prototype_vectors is None:
                prototype_texts = [CATEGORY_SEMANTIC_PROTOTYPES[c] for c in categories]
                self._semantic_prototype_vectors = engine.encode_batch(prototype_texts)
            query = engine.encode(text[:4000])
            if query is None or getattr(query, "size", 0) == 0:
                return {}
            result = {}
            for idx, cat in enumerate(categories):
                vec = self._semantic_prototype_vectors[idx]
                if getattr(vec, "size", 0) == 0 or vec.shape != query.shape:
                    continue
                similarity = float((query * vec).sum())
                # EmbeddingEngine normalizes vectors. Clamp for robust fallback behavior.
                result[cat] = max(-1.0, min(1.0, similarity))
            return result
        except Exception:
            return {}

    def _init_zero_shot(self):
        try:
            from transformers import pipeline
            self._zero_shot_pipeline = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
            self._zero_shot_available = True
        except Exception:
            self._zero_shot_available = False

    def classify(self, text: str) -> Tuple[str, str]:
        """Backward compatible single-text classification."""
        category, confidence, source, _ = self.classify_multi_signal(text=text)
        return category, source

    def classify_multi_signal(
        self,
        text: str = "",
        filename: str = "",
        file_type: str = "",
        pii_types: Optional[List[str]] = None,
        ocr_confidence: Optional[float] = None
    ) -> Tuple[str, float, str, Dict[str, Any]]:
        """
        Multi-signal categorization combining filename, OCR/text, PII, and file metadata.
        Returns (category, confidence, source, evidence_dict).
        """
        text_lower = (text or "").lower()
        filename_clean = re.sub(r"[^\w\s]", " ", (filename or "").lower())
        fn_tokens = [t.strip() for t in filename_clean.split() if len(t.strip()) > 1]
        pii_list = pii_types or []

        expanded_terms = []
        for token in fn_tokens:
            if token in FILENAME_ABBREVIATIONS:
                expanded_terms.append(FILENAME_ABBREVIATIONS[token])
            else:
                expanded_terms.append(token)

        filename_expanded_text = " ".join(expanded_terms)

        scores: Dict[str, float] = {cat: 0.0 for cat in CATEGORY_PATTERNS}
        matched_details: Dict[str, List[str]] = {cat: [] for cat in CATEGORY_PATTERNS}

        # 1. Filename signal. Useful context, but not strong enough to
        # dominate the full document content by itself.
        for cat, patterns in CATEGORY_PATTERNS.items():
            for p in patterns:
                if re.search(p, filename_expanded_text):
                    scores[cat] += 2.0
                    matched_details[cat].append(f"filename:'{p}'")
                elif re.search(p, filename_clean):
                    scores[cat] += 2.0
                    matched_details[cat].append(f"filename:'{p}'")

        # 2. OCR/Text signal. Count distinct evidence patterns instead of
        # repeated mentions of the same word.
        if text_lower:
            text_weight = 1.5
            if ocr_confidence is not None:
                try:
                    text_weight *= max(0.35, min(1.0, float(ocr_confidence)))
                except (TypeError, ValueError):
                    pass
            for cat, patterns in CATEGORY_PATTERNS.items():
                distinct_matches = 0
                for p in patterns:
                    count = len(re.findall(p, text_lower))
                    if count > 0:
                        distinct_matches += 1
                        matched_details[cat].append(f"text:'{p}'({count})")
                scores[cat] += min(6.0, distinct_matches * text_weight)

        # 3. Existing local semantic signal (optional, cached and offline-first).
        semantic_scores = self._semantic_scores(text_lower) if text_lower else {}
        for cat, similarity in semantic_scores.items():
            # Only meaningful similarity contributes. This avoids turning weak generic
            # embeddings into fake high-confidence classifications.
            contribution = max(0.0, similarity - 0.35) * 7.0
            if contribution > 0:
                scores[cat] += min(4.0, contribution)

        # 4. PII / Entity Signal Evaluation
        if any(p in ("PAN", "AADHAAR", "CREDIT_CARD", "PASSPORT") for p in pii_list):
            scores["Identity"] += 4.0
            matched_details["Identity"].append("pii:identity_records")
        if "CREDIT_CARD" in pii_list:
            scores["Financial"] += 3.0
            matched_details["Financial"].append("pii:financial_card")

        # 5. Context/intent reasoning. These bounded adjustments combine
        # multiple signals so generic financial words cannot dominate.
        education_patterns = (
            r"\bcollege\b", r"\buniversity\b", r"\bsemester\b",
            r"\bstudent\b", r"\bsyllabus\b", r"\bcourse\b",
            r"\blecture\b", r"\bexam\b", r"\bacademic\b"
        )
        assignment_patterns = (
            r"\bassignments?\b", r"\bhomework\b", r"\bproblem set\b",
            r"\bdsa\b", r"\balgorithms?\b", r"\blab report\b",
            r"\bsubmission\b", r"\bquiz\b", r"\bdata structures?\b"
        )
        financial_artifacts = (
            r"\binvoices?\b", r"\breceipts?\b", r"\bpayment\b",
            r"\bbank statement\b", r"\btransaction\b", r"\btax\b",
            r"\bpaystub\b", r"\bamount due\b"
        )
        certificate_patterns = (
            r"\bcertificates?\b", r"\bcertification\b", r"\bawarded\b",
            r"\bcompletion\b", r"\bdiploma\b", r"\bcredential\b"
        )
        context_blob = f"{filename_expanded_text} {text_lower[:8000]}"

        def is_negated_match(blob: str, match_start: int) -> bool:
            """Treat artifact mentions inside explicit negation clauses as non-evidence."""
            prefix = blob[max(0, match_start - 160):match_start].lower()
            clause = re.split(r"[.!?;\n]", prefix)[-1]
            return bool(re.search(
                r"\b(?:no|without|never|not|does not contain|doesn\'?t contain|contains no)\b",
                clause,
            ))

        education_hits = sum(1 for p in education_patterns if re.search(p, context_blob))
        assignment_hits = sum(1 for p in assignment_patterns if re.search(p, context_blob))

        # Count only positive financial-artifact evidence.
        # Example: "contains no receipt, payment, invoice..." should not
        # classify an otherwise academic document as Financial.
        finance_artifact_hits = 0
        for p in financial_artifacts:
            match = re.search(p, context_blob)
            if match and not is_negated_match(context_blob, match.start()):
                finance_artifact_hits += 1

        certificate_hits = sum(1 for p in certificate_patterns if re.search(p, context_blob))

        if assignment_hits >= 2:
            scores["Assignment"] += 2.5
            matched_details["Assignment"].append("context:assignment_intent")
        elif assignment_hits == 1 and education_hits >= 2:
            scores["Assignment"] += 1.0
            matched_details["Assignment"].append("context:academic_assignment")

        if certificate_hits >= 2:
            scores["Certificate"] += 2.0
            matched_details["Certificate"].append("context:certificate_intent")

        if education_hits >= 2 and finance_artifact_hits == 0:
            scores["Financial"] = min(scores["Financial"], 3.5)
            matched_details["Financial"].append(
                "context:generic_financial_terms_in_education_context_capped"
            )
            scores["Academic"] += min(2.5, 0.75 * education_hits)
            matched_details["Academic"].append(
                f"context:education_intent({education_hits})"
            )

        if finance_artifact_hits >= 2:
            scores["Financial"] += min(2.5, 0.75 * finance_artifact_hits)
            matched_details["Financial"].append(
                f"context:financial_artifact_cluster({finance_artifact_hits})"
            )

        # Let a strong local semantic signal provide a modest correction when
        # rule-based classification has not established a decisive lead.
        if semantic_scores:
            semantic_ranked_pre = sorted(semantic_scores.items(), key=lambda x: x[1], reverse=True)
            semantic_best, semantic_best_score = semantic_ranked_pre[0]
            rule_best = max(scores.items(), key=lambda x: x[1])[0]
            if semantic_best != rule_best and semantic_best_score >= 0.55:
                scores[semantic_best] += 0.75
                matched_details[semantic_best].append(
                    f"semantic:context_guard({semantic_best_score:.2f})"
                )

        # MANUAL_AI_QUALITY_V1
        # MANUAL_AI_QUALITY_V2_NEGATION

        # Determine best category and calculate confidence
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_cat, top_score = sorted_scores[0]
        second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0.0

        if top_score == 0.0:
            # Fallback zero-shot if enabled
            if self._zero_shot_available and self._zero_shot_pipeline is not None and text_lower:
                try:
                    candidate_labels = list(CATEGORY_PATTERNS.keys())
                    res = self._zero_shot_pipeline(text[:1000], candidate_labels)
                    best_label = res["labels"][0]
                    score_val = float(res["scores"][0])
                    return best_label, round(score_val, 2), "zero_shot", {
                        "category": best_label,
                        "confidence": round(score_val, 2),
                        "status_label": "PENDING" if score_val >= 0.70 else "NEEDS_REVIEW",
                        "reason": f"Categorized via zero-shot model as {best_label}"
                    }
                except Exception:
                    pass

            return "General", 0.30, "fallback", {
                "category": "General",
                "confidence": 0.30,
                "status_label": "NEEDS_REVIEW",
                "filename_signals": fn_tokens,
                "matched_patterns": [],
                "semantic_scores": {},
                "reason": "Insufficient document signals found; default category remains General and needs review."
            }

        # Calculate confidence based on signal strength and ambiguity.
        top_semantic = semantic_scores.get(top_cat, 0.0) if semantic_scores else 0.0
        if top_score >= 7.0:
            confidence = min(0.96, 0.78 + (top_score * 0.02))
        elif top_score >= 4.0:
            confidence = min(0.90, 0.66 + (top_score * 0.04))
        elif top_score >= 2.5:
            confidence = min(0.85, 0.60 + (top_score * 0.05))
        else:
            confidence = 0.55

        if top_semantic >= 0.60:
            confidence = min(0.96, confidence + 0.04)
        elif top_semantic >= 0.50:
            confidence = min(0.92, confidence + 0.02)

        # Disagreement penalty if second category is close
        if second_score > 0 and (top_score - second_score) <= 1.5:
            confidence *= 0.85

        confidence = round(confidence, 2)
        status_label = "PENDING" if confidence >= 0.70 else "NEEDS_REVIEW"

        semantic_ranked = sorted(semantic_scores.items(), key=lambda x: x[1], reverse=True) if semantic_scores else []
        evidence = {
            "category": top_cat,
            "confidence": confidence,
            "status_label": status_label,
            "filename_signals": fn_tokens,
            "expanded_terms": expanded_terms,
            "matched_patterns": matched_details[top_cat],
            "pii_signals": pii_list,
            "file_type": file_type,
            "semantic_top_match": semantic_ranked[0][0] if semantic_ranked else None,
            "semantic_similarity": round(semantic_ranked[0][1], 3) if semantic_ranked else None,
            "semantic_scores": {k: round(v, 3) for k, v in semantic_scores.items()} if semantic_scores else {},
            "reason": self._build_reason(top_cat, filename, matched_details[top_cat], semantic_ranked, pii_list)
        }

        source = "multi_signal+semantic" if semantic_scores else "multi_signal"
        return top_cat, confidence, source, evidence

    @staticmethod
    def _build_reason(category: str, filename: str, matched_patterns: List[str], semantic_ranked: List[Tuple[str, float]], pii_types: List[str]) -> str:
        parts = []
        if filename:
            parts.append(f"filename '{filename}'")
        if matched_patterns:
            parts.append(f"{len(matched_patterns)} textual/OCR evidence signal(s)")
        if semantic_ranked and semantic_ranked[0][0] == category:
            parts.append(f"semantic similarity {semantic_ranked[0][1]:.2f} to {category.lower()} context")
        if pii_types:
            parts.append(f"PII signal(s): {', '.join(pii_types[:3])}")
        if not parts:
            return f"Insufficient evidence to confidently classify this document as {category}."
        return f"Suggested {category} using " + ", ".join(parts) + "."
