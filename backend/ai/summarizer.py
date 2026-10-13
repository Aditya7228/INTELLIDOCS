import re
from typing import Optional, List
from collections import Counter
from backend.config import settings

STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with",
    "by", "from", "up", "about", "into", "over", "after", "is", "are", "was", "were",
    "be", "been", "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "should", "can", "could", "may", "might", "must", "shall", "this", "that", "these",
    "those", "i", "you", "he", "she", "it", "we", "they", "pdf", "docx", "file", "page",
    "document", "image", "jpg", "png", "txt", "general", "uploaded", "created"
}

class Summarizer:
    """
    Document summarization and key topic extraction component.
    Provides Transformer-based summarization when available, with a clean local
    extractive summarization fallback and contextual keyword extraction.
    """
    def __init__(self):
        self._pipeline = None
        self._available = False
        if settings.ENABLE_SUMMARIZER:
            self._init_summarizer()

    def _init_summarizer(self):
        try:
            from transformers import pipeline
            self._pipeline = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")
            self._available = True
        except Exception:
            self._available = False

    def is_available(self) -> bool:
        return self._available and self._pipeline is not None

    def summarize(self, text: str, max_length: int = 150) -> str:
        """Return a short, readable summary instead of echoing OCR text.

        OCR documents often use line breaks rather than sentence punctuation. Treat
        structured OCR as labeled facts, omit common personal identifiers, and
        select only a small number of useful lines. Normal prose can still use the
        optional transformer model, with an extractive fallback.
        """
        if not text or len(text.strip()) < 30:
            return "No extractable text content available for summarization."

        clean_text = str(text).replace("\x00", " ").replace("\f", "\n")
        clean_text = re.sub(r"\r\n?", "\n", clean_text)
        clean_text = re.sub(r"[ \t]+", " ", clean_text)
        clean_text = re.sub(r" *\n *", "\n", clean_text).strip()

        raw_lines = [re.sub(r"\s+", " ", line).strip(" \t•*-\u2022")
                     for line in clean_text.splitlines()]
        raw_lines = [line for line in raw_lines if line]

        # Merge a short institution/name line with its immediately following
        # college/school/university descriptor so the summary keeps context.
        merged_lines = []
        i = 0
        while i < len(raw_lines):
            current = raw_lines[i]
            if (i < 4 and i + 1 < len(raw_lines) and len(current) >= 10
                    and re.search(r"\b(college|university|institute|school|academy)\b", raw_lines[i + 1], re.I)
                    and len(raw_lines[i + 1]) <= 100):
                merged_lines.append(current + " — " + raw_lines[i + 1])
                i += 2
            else:
                merged_lines.append(current)
                i += 1
        raw_lines = merged_lines

        # These fields can exist in extracted text, but they are not useful in a
        # high-level summary and may unnecessarily repeat personal identifiers.
        private_line = re.compile(
            r"\b(student\s*name|father\s*name|mother\s*name|mobile(?:\s*no)?|"
            r"phone(?:\s*no)?|e-?mail|email\s*id|prn\s*no?|transaction\s*id|"
            r"receipt\s*no|roll\s*no|enrol(?:l)?ment\s*(?:no|number)|"
            r"account\s*no|permanent\s*address)\b",
            re.IGNORECASE,
        )
        label_pattern = re.compile(
            r"\b(total|grand total|amount|amount paid|balance due|mode of payment|"
            r"payment mode|receipt|invoice|fee|tuition|academic year|course term|"
            r"semester|branch|college|university|institution|conclusion|findings|"
            r"recommendation|purpose|subject|result|deadline|due date)\b",
            re.IGNORECASE,
        )
        structured_label = re.compile(
            r"\b(total|amount|paid|payment|receipt|invoice|fee|tuition|course term|"
            r"academic year|semester|branch|student name|mobile|transaction id)\b",
            re.IGNORECASE,
        )
        structured = (
            len(raw_lines) >= 7
            or sum(1 for line in raw_lines if structured_label.search(line)) >= 3
        )

        # For flattened OCR with few line breaks, split before common field labels
        # before falling back to ordinary sentence boundaries.
        units = raw_lines if structured else re.split(r"(?<=[.!?])\s+", clean_text)
        if structured and len(units) < 4:
            units = re.split(
                r"(?i)(?=\b(?:receipt|invoice|total|amount paid|mode of payment|"
                r"payment mode|academic year|course term|branch|college|university|"
                r"student name|mobile no|transaction id)\s*:?\s*)",
                clean_text,
            )
        units = [re.sub(r"\s+", " ", unit).strip(" \t•*-\u2022")
                 for unit in units if unit and unit.strip()]

        # When OCR did not expose any useful line or sentence boundaries, cap the
        # input into readable chunks rather than returning the entire extraction.
        expanded = []
        for unit in units:
            if len(unit) > 420 and not structured:
                expanded.extend(re.split(r"(?<=[.!?;])\s+", unit))
            else:
                expanded.append(unit)
        units = [u.strip() for u in expanded if u and u.strip()]

        candidates = []
        has_total_line = any(
            re.search(r"\b(grand total|total|amount paid|balance due)\b", unit, re.I)
            for unit in units
        )
        all_words = [
            word.lower() for word in re.findall(r"\b[a-zA-Z]{3,}\b", clean_text)
            if word.lower() not in STOP_WORDS
        ]
        word_freq = Counter(all_words)
        high_value = re.compile(
            r"\b(grand total|total|amount paid|balance due|mode of payment|payment mode|"
            r"payment|receipt|invoice|fees?|tuition|academic year|course term|semester|"
            r"institution|university|college|branch|course|conclusion|key findings|"
            r"recommendations?|purpose|subject|deadline|due date|problem|solution)\b",
            re.IGNORECASE,
        )
        financial_value = re.compile(
            r"(?:₹|\brs\.?\s*)?\s*\d[\d,]*(?:\.\d{1,2})?\b|\b(?:online|cash|upi|card|transfer)\b",
            re.IGNORECASE,
        )

        for idx, unit in enumerate(units):
            short_artifact_label = bool(re.fullmatch(r"(?i)(receipt|invoice|certificate|report|letter)", unit))
            if short_artifact_label:
                unit = "Document type: " + unit.capitalize()
            key_value_line = bool(re.match(r"(?i)^(grand total|total|amount paid|balance due)\b.*\d", unit))
            if (len(unit) < 10 and not short_artifact_label and not key_value_line) or private_line.search(unit):
                continue
            alpha_count = sum(ch.isalpha() for ch in unit)
            if alpha_count < 8 and not short_artifact_label and not key_value_line:
                continue
            if alpha_count / max(len(unit), 1) < 0.38 and not key_value_line:
                continue

            words = [
                word.lower() for word in re.findall(r"\b[a-zA-Z]{3,}\b", unit)
                if word.lower() not in STOP_WORDS
            ]
            freq_score = sum(word_freq[word] for word in words) / max(len(words) + 1, 1)
            score = freq_score + (1.0 / (idx + 1))
            if high_value.search(unit):
                score += 2.8
            if re.search(r"\b(college|university|institution|school|institute)\b", unit, re.I):
                score += 2.0
            if has_total_line and re.search(r"\b(fee|tuition|development fee|library fee|exam fee)\b", unit, re.I) and not re.search(r"\b(grand total|total|amount paid|balance due)\b", unit, re.I):
                score -= 2.7
            if re.search(r"\b(grand total|total|amount paid|balance due)\b", unit, re.I):
                score += 5.0
            elif re.search(r"\b(mode of payment|payment mode|payment)\b", unit, re.I):
                score += 3.2
            if financial_value.search(unit) and re.search(r"\b(total|amount|paid|fee|payment|term|year|date)\b", unit, re.I):
                score += 1.5
            if re.match(r"^\d+\s+.*\b(fee|charge)\b", unit, re.I) and not re.search(r"\b(total|grand total|amount paid)\b", unit, re.I):
                score -= 1.8
            if idx < 3 and len(unit) <= 110:
                score += 0.8
            if len(unit) > 220:
                score -= min((len(unit) - 220) / 100, 2.5)
            candidates.append((idx, score, unit))

        if not candidates:
            # Conservative final fallback: return a clipped, PII-filtered piece,
            # never the full raw extraction.
            fallback = next((u for u in units if len(u) >= 20 and not private_line.search(u)), "")
            fallback = fallback[:220].rstrip()
            return ("• " + fallback + ("…" if len(fallback) >= 220 else "")) if fallback else "No clear summary could be extracted from this document."

        # Model summarization is reserved for ordinary prose. For forms/receipts,
        # deterministic fact selection avoids hallucinating or copying OCR dumps.
        if not structured and self.is_available() and len(clean_text) >= 100:
            try:
                sample = clean_text[:4000]
                res = self._pipeline(sample, max_length=min(max_length, 110), min_length=25, do_sample=False)
                model_summary = str(res[0].get("summary_text", "")).strip()
                model_units = [
                    re.sub(r"\s+", " ", piece).strip()
                    for piece in re.split(r"(?<=[.!?])\s+|\n+", model_summary)
                    if piece and len(piece.strip()) >= 12 and not private_line.search(piece)
                ]
                if model_units and len(model_summary) < len(clean_text) * 0.7:
                    return "\n".join("• " + piece[:220].rstrip() for piece in model_units[:4])
            except Exception:
                # Keep local extractive summarization available when the optional
                # transformer model is not installed or fails to load/run.
                pass

        max_bullets = 5 if structured else 3
        selected = sorted(candidates, key=lambda item: item[1], reverse=True)[:max_bullets]
        selected.sort(key=lambda item: item[0])
        bullets = []
        seen = set()
        for _, _, unit in selected:
            compact = re.sub(r"\s+", " ", unit).strip()
            if len(compact) > 190:
                compact = compact[:187].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"
            key = compact.casefold()
            if key in seen or any(key in previous or previous in key for previous in seen):
                continue
            seen.add(key)
            bullets.append("• " + compact)
        return "\n".join(bullets[:max_bullets]) if bullets else "No clear summary could be extracted from this document."

    def extract_key_topics(self, text: str, filename: Optional[str] = None, category: Optional[str] = None) -> List[str]:
        topics = []
        if category and category.lower() not in ("general", "uncategorized"):
            topics.append(category.strip().title())

        full_content = (text or "") + " " + (filename or "")
        clean_words = [w for w in re.findall(r"\b[a-zA-Z]{3,}\b", full_content) if w.lower() not in STOP_WORDS]

        if not clean_words:
            return topics[:5]

        # Single word frequencies
        counts = Counter([w.capitalize() for w in clean_words])

        # Bigram frequencies
        bigrams = []
        for i in range(len(clean_words) - 1):
            w1, w2 = clean_words[i], clean_words[i + 1]
            bigrams.append(f"{w1.capitalize()} {w2.capitalize()}")
        bigram_counts = Counter(bigrams)

        # Select top bigrams first (if count >= 2 or strong relevance)
        for bg, count in bigram_counts.most_common(5):
            if count >= 2 or len(clean_words) < 50:
                if bg not in topics and not any(bg.lower() in t.lower() for t in topics):
                    topics.append(bg)

        # Select top single words
        for word, count in counts.most_common(10):
            if len(topics) >= 7:
                break
            if word not in topics and not any(word.lower() in t.lower() for t in topics):
                topics.append(word)

        return topics[:6]
# === IntelliDocs Summary PII Output Guard V9 ===
# Defense-in-depth for all summary paths, including the optional transformer output.
_ID_V9_ORIGINAL_SUMMARIZE = Summarizer.summarize
_ID_V9_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_ID_V9_IN_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s.-]?)?[6-9]\d{9}(?!\d)")
_ID_V9_AADHAAR_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)")
_ID_V9_PAN_RE = re.compile(r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b")
_ID_V9_PRIVATE_FIELD_RE = re.compile(
    r"(?i)\b(student\s*name|father\s*name|mother\s*name|mobile(?:\s*no)?|phone(?:\s*no)?|"
    r"e-?mail(?:\s*id)?|prn\s*no?|roll\s*no|enrol(?:l)?ment\s*(?:no|number)|"
    r"account\s*no|transaction\s*id|receipt\s*no|permanent\s*address|aadhaar(?:\s*no)?|pan(?:\s*no|\s*number)?)\s*[:#-]\s*[^|;\n]+"
)


def _id_v9_redact_summary_pii(self, text, max_length=150):
    output = str(_ID_V9_ORIGINAL_SUMMARIZE(self, text, max_length=max_length) or "")
    output = _ID_V9_PRIVATE_FIELD_RE.sub(r"\1: [redacted]", output)
    output = _ID_V9_EMAIL_RE.sub("[redacted email]", output)
    output = _ID_V9_IN_PHONE_RE.sub("[redacted phone]", output)
    output = _ID_V9_AADHAAR_RE.sub("[redacted identifier]", output)
    output = _ID_V9_PAN_RE.sub("[redacted identifier]", output)
    return output


Summarizer.summarize = _id_v9_redact_summary_pii

# === IntelliDocs Document Detail Fixes V11 ===
# Produce a title-aware, extractive summary and identify legacy summaries that
# are visibly unrelated to a quoted document/project title.
import os as _id_v11_os
import re as _id_v11_re

_ID_V11_BASE_SUMMARIZE = Summarizer.summarize
_ID_V11_SUMMARY_STOP = set(STOP_WORDS) | {
    "project", "based", "learning", "review", "report", "document", "documents",
    "system", "systems", "pdf", "overview", "introduction", "conclusion",
    "abstract", "chapter", "page", "pages", "roll", "number", "name", "mr", "mrs",
    "ms", "student", "students", "details", "general", "information",
}
_ID_V11_SENTENCE_PII_RE = re.compile(
    r"(?i)\b(?:student\s*name|father\s*name|mother\s*name|mobile(?:\s*no)?|"
    r"phone(?:\s*no)?|e-?mail(?:\s*id)?|prn\s*no?|roll\s*no|"
    r"enrol(?:l)?ment\s*(?:no|number)|account\s*no|transaction\s*id|"
    r"receipt\s*no|permanent\s*address|aadhaar(?:\s*no)?|pan(?:\s*no|\s*number)?)\s*[:#-]\s*[^|;\n]+"
)
_ID_V11_GENERIC_START_RE = re.compile(
    r"(?i)^(?:detect|supports?|provides?|includes?|create|use|click|select|open|"
    r"module\s*:|ai\s*&\s*search\s*:|features?\s*:|key features?\s*:|contents?\s*:|"
    r"table of contents|page\s+\d+\b)"
)
_ID_V11_SECTION_RE = re.compile(
    r"(?i)\b(abstract|introduction|overview|objective|objectives|purpose|problem statement|"
    r"proposed system|methodology|approach|solution|architecture|workflow|results|conclusion|"
    r"recommendations?|key findings|in this project|the project|the system aims)\b"
)


def _id_v11_subject_from_filename(filename):
    name = _id_v11_os.path.basename(str(filename or ""))
    name = _id_v11_re.sub(r"\.[A-Za-z0-9]{1,8}$", "", name)
    # A quoted project/title name is the strongest filename context and avoids
    # carrying roll numbers or contributor names into the summary.
    match = _id_v11_re.search(r'[\"“‘]([^\"”’]{4,100})[\"”’]', name)
    if match:
        subject = _id_v11_re.sub(r"\s+", " ", match.group(1)).strip(" .-_\t")
        return subject[:100]
    cleaned = name.replace("_", " ").replace("-", " ")
    cleaned = _id_v11_re.sub(r"(?i)\b(by|roll\s*no|roll\s*number|mr|mrs|ms)\b.*$", "", cleaned)
    cleaned = _id_v11_re.sub(
        r"(?i)^(?:(?:project\s+based\s+learning|pbl)\s+)?(?:review\s*\d*\s*)?(?:on\s+)?", "", cleaned
    ).strip(" .-_\t")
    cleaned = _id_v11_re.sub(r"\s+", " ", cleaned)
    if not cleaned or len(cleaned) > 100:
        return "uploaded document"
    return cleaned[:100]


def _id_v11_stem(token):
    word = str(token or "").lower()
    if len(word) > 6 and word.endswith("ization"):
        return word[:-7] + "ize"
    if len(word) > 5 and word.endswith("ation"):
        return word[:-5]
    if len(word) > 5 and word.endswith("ing"):
        return word[:-3]
    if len(word) > 4 and word.endswith("ed"):
        return word[:-2]
    if len(word) > 4 and word.endswith("s"):
        return word[:-1]
    return word


def _id_v11_title_terms(subject):
    words = _id_v11_re.findall(r"[A-Za-z]{3,}", str(subject or "").lower())
    return [_id_v11_stem(w) for w in words if w not in _ID_V11_SUMMARY_STOP]


def _id_v11_summary_needs_refresh(summary, filename):
    text = str(summary or "").strip()
    if not text:
        return True
    subject = _id_v11_subject_from_filename(filename)
    if subject == "uploaded document":
        return False
    terms = _id_v11_title_terms(subject)
    # Only make a title-alignment judgement when the title has enough meaningful
    # words. Documents with ordinary names retain the old generated summary.
    if len(terms) < 2:
        return False
    content = [_id_v11_stem(w) for w in _id_v11_re.findall(r"[A-Za-z]{3,}", text.lower())]
    matched = sum(1 for term in terms if any(word == term or word.startswith(term) or term.startswith(word) for word in content))
    return (matched / max(len(terms), 1)) < 0.65


def _id_v11_summarize_document(self, text, filename=None, max_length=150):
    source = str(text or "").replace("\x00", " ").replace("\f", "\n")
    source = _id_v11_re.sub(r"\r\n?", "\n", source)
    source = _id_v11_re.sub(r"[ \t]+", " ", source)
    source = _id_v11_re.sub(r" *\n *", "\n", source).strip()
    if len(source) < 30:
        return _ID_V11_BASE_SUMMARIZE(self, source, max_length=max_length)

    subject = _id_v11_subject_from_filename(filename)
    if subject == "uploaded document":
        # Use the existing implementation for filenames that contain no usable
        # title context, while keeping its PII guard intact.
        return _ID_V11_BASE_SUMMARIZE(self, source, max_length=max_length)

    terms = _id_v11_title_terms(subject)
    sentences = _id_v11_re.split(r"(?<=[.!?])\s+|\n+", source)
    units = []
    for idx, item in enumerate(sentences):
        unit = _id_v11_re.sub(r"\s+", " ", item).strip(" \t•*-\u2022")
        if len(unit) < 45:
            continue
        unit = _ID_V11_SENTENCE_PII_RE.sub("", unit).strip(" ,;:-")
        if len(unit) < 45 or len(unit) > 480:
            continue
        if _id_v11_re.search(r"(?i)^\s*(?:page\s+)?\d{1,3}\s*$", unit):
            continue
        tokens = [_id_v11_stem(w) for w in _id_v11_re.findall(r"[A-Za-z]{3,}", unit.lower()) if w not in _ID_V11_SUMMARY_STOP]
        if len(tokens) < 7:
            continue
        alpha_ratio = sum(ch.isalpha() for ch in unit) / max(len(unit), 1)
        if alpha_ratio < 0.48:
            continue
        overlap = sum(1 for term in terms if any(word == term or word.startswith(term) or term.startswith(word) for word in tokens))
        # Favour title-relevant text and conventional abstract/overview passages;
        # avoid letting a random feature checklist dominate the entire summary.
        score = (overlap * 3.4) + (2.2 if _ID_V11_SECTION_RE.search(unit) else 0.0)
        score += max(0.0, 1.8 - idx * 0.11)
        if _ID_V11_GENERIC_START_RE.search(unit):
            score -= 2.2
        if len(unit) > 320:
            score -= 0.8
        units.append((score, idx, unit, set(tokens)))

    units.sort(key=lambda x: (-x[0], x[1]))
    selected = []
    selected_terms = []
    for score, idx, unit, token_set in units:
        # Keep meaningful detail but avoid picking several sentences that repeat
        # the same subsystem or feature list.
        if selected and any(len(token_set & prior) / max(len(token_set | prior), 1) > 0.72 for prior in selected_terms):
            continue
        selected.append((idx, unit))
        selected_terms.append(token_set)
        if len(selected) >= 3:
            break
    selected.sort(key=lambda x: x[0])

    # Never invent facts: the title supplies context; detail sentences come only
    # from this document's own extracted text.
    pieces = [f'This document is about “{subject}.”']
    for _, unit in selected:
        unit = unit[:260].rstrip(" ,;:-")
        if unit and unit[-1] not in ".!?…":
            unit += "."
        if unit and unit.casefold() not in {p.casefold() for p in pieces}:
            pieces.append(unit)
    if len(pieces) == 1:
        fallback = _ID_V11_BASE_SUMMARIZE(self, source, max_length=max_length)
        if fallback and not fallback.lower().startswith("no "):
            pieces.append(fallback.replace("\n• ", " ").replace("• ", " ").strip())
        else:
            pieces.append("The extracted text does not contain enough clear detail for a more reliable summary.")

    output = "\n".join(pieces[:4])
    # Reuse the V9 output redaction patterns if present. PII stays out of the
    # newly added title context and selected extractive lines.
    for name in ("_ID_V9_PRIVATE_FIELD_RE", "_ID_V9_EMAIL_RE", "_ID_V9_IN_PHONE_RE", "_ID_V9_AADHAAR_RE", "_ID_V9_PAN_RE"):
        pattern = globals().get(name)
        if pattern is None:
            continue
        if name == "_ID_V9_PRIVATE_FIELD_RE":
            output = pattern.sub(r"\1: [redacted]", output)
        elif name == "_ID_V9_EMAIL_RE":
            output = pattern.sub("[redacted email]", output)
        elif name == "_ID_V9_IN_PHONE_RE":
            output = pattern.sub("[redacted phone]", output)
        else:
            output = pattern.sub("[redacted identifier]", output)
    return output


Summarizer.summarize_document = _id_v11_summarize_document
Summarizer.summary_needs_refresh = staticmethod(_id_v11_summary_needs_refresh)
