from backend.ai.classifier import DocumentClassifier
from backend.core.organization_service import OrganizationService


def test_assignment_context_beats_generic_academic_terms():
    c = DocumentClassifier(embedding_engine=None)
    category, confidence, source, evidence = c.classify_multi_signal(
        text="College semester 3 assignment about data structures, algorithms, stack and queue.",
        filename="DSA_Assignment_Sem3.pdf",
        file_type="pdf",
    )
    assert category == "Assignment"
    assert confidence >= 0.70
    assert evidence["status_label"] == "PENDING"


def test_fee_receipt_stays_financial():
    c = DocumentClassifier(embedding_engine=None)
    category, confidence, source, evidence = c.classify_multi_signal(
        text="College semester 3 tuition fee payment receipt. Amount paid for university fees.",
        filename="College_Fee_Receipt.pdf",
        file_type="pdf",
    )
    assert category == "Financial"
    assert confidence >= 0.70


def test_generic_financial_words_do_not_overpower_academic_document():
    c = DocumentClassifier(embedding_engine=None)
    category, confidence, source, evidence = c.classify_multi_signal(
        text=(
            "College semester 3 academic course outline for students. "
            "This document mentions fee information but contains no receipt, "
            "payment, invoice, bank statement, or transaction."
        ),
        filename="Semester3_Course_Outline.pdf",
        file_type="pdf",
    )
    assert category != "Financial"


def test_sensitivity_recommendation_is_independent_of_category():
    s = OrganizationService(embedding_engine=None)
    rec = s.sensitivity_recommendation(
        text="Student PAN ABCDE1234F and email student@example.com",
        sensitivity="pii",
        pii_types=["PAN", "EMAIL"],
    )
    assert rec["sensitivity"] == "pii"
    assert rec["display_level"] == "Confidential"
    assert rec["confidence"] >= 0.88
    assert "PAN" in rec["pii_types"]
    assert "EMAIL" in rec["pii_types"]


def test_sensitivity_label_normalization():
    s = OrganizationService(embedding_engine=None)
    assert s.normalize_sensitivity("Public") == "public"
    assert s.normalize_sensitivity("Internal") == "internal"
    assert s.normalize_sensitivity("Confidential") == "pii"
    assert s.normalize_sensitivity("Restricted") == "pii"
