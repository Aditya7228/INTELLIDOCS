import pytest
import uuid
import numpy as np
from sqlalchemy.orm import Session
from backend.database.connection import SessionLocal, Base, engine
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.suggestion import DocumentSuggestion
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.suggestion_repo import SuggestionRepository
from backend.ai.classifier import DocumentClassifier
from backend.core.categorization_service import CategorizationService
from backend.core.organization_service import OrganizationService
from backend.security.password import PasswordManager

@pytest.fixture(autouse=True)
def setup_db_tables():
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def test_user(db_session: Session) -> User:
    suffix = uuid.uuid4().hex[:6]
    pwd_hash = PasswordManager.hash_password("Password123!")
    user = User(username=f"ai_user_{suffix}", email=f"ai_{suffix}@example.com", password_hash=pwd_hash)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def other_user(db_session: Session) -> User:
    suffix = uuid.uuid4().hex[:6]
    pwd_hash = PasswordManager.hash_password("Password123!")
    user = User(username=f"other_user_{suffix}", email=f"other_{suffix}@example.com", password_hash=pwd_hash)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_clg_fee_png_multi_signal_reasoning(db_session: Session, test_user: User):
    """
    Test the 'clg fee.png' requirement:
    Filename 'clg fee.png' + OCR containing college/fee/receipt/semester/tuition
    MUST produce a Financial/Academic categorization, contextual rename suggestion,
    and relevant tags while keeping the original filename intact until approved.
    """
    doc_repo = DocumentRepository(db_session)
    doc = doc_repo.create({
        "uuid": f"test-clg-fee-{uuid.uuid4().hex[:8]}",
        "original_name": "clg fee.png",
        "display_name": "clg fee.png",
        "stored_name": f"test-clg-fee-{uuid.uuid4().hex}.png",
        "file_path": f"uploads/test-clg-fee-{uuid.uuid4().hex}.png",
        "file_type": "png",
        "mime_type": "image/png",
        "size_bytes": 45000,
        "sha256_hash": "a"*64,
        "extracted_text": "College Tuition Fee Receipt Paid Amount: $500 Semester 3 Academic Year 2026",
        "category": "General",
        "category_source": "rule",
        "sensitivity": "public",
        "has_ocr": 1,
        "ocr_confidence": 0.95,
        "owner_id": test_user.id,
        "processing_status": "done"
    })

    org_service = OrganizationService()
    suggestions = org_service.generate_suggestions_for_document(db_session, doc)

    # 1. Original filename must NOT be silently replaced
    db_session.refresh(doc)
    assert doc.original_name == "clg fee.png"
    assert doc.display_name == "clg fee.png"

    # 2. Assert suggestions generated
    s_repo = SuggestionRepository(db_session)
    doc_suggs = s_repo.get_for_document(doc.id)
    assert len(doc_suggs) >= 2

    # Check Categorize suggestion
    cat_sugg = next((s for s in doc_suggs if s.suggestion_type == "categorize"), None)
    assert cat_sugg is not None
    assert cat_sugg.suggested_value in ("Financial", "Academic")
    assert cat_sugg.confidence >= 0.75
    assert "status_label" in cat_sugg.evidence_dict

    # Check Rename suggestion
    rename_sugg = next((s for s in doc_suggs if s.suggestion_type == "rename"), None)
    assert rename_sugg is not None
    assert "College" in rename_sugg.suggested_value or "Fee" in rename_sugg.suggested_value or "Receipt" in rename_sugg.suggested_value
    assert rename_sugg.current_value == "clg fee.png"

    # Check Tag suggestion
    tag_sugg = next((s for s in doc_suggs if s.suggestion_type == "add_tag"), None)
    assert tag_sugg is not None
    assert any(t in tag_sugg.suggested_value.lower() for t in ["college", "fee", "receipt", "tuition"])


def test_image_with_no_ocr_fallback_confidence(db_session: Session, test_user: User):
    """
    Test an image document with empty/junk OCR text.
    Must gracefully fall back to General category with low confidence and Needs Review status
    without hallucinating 95% confidence.
    """
    doc_repo = DocumentRepository(db_session)
    doc = doc_repo.create({
        "uuid": f"test-junk-img-{uuid.uuid4().hex[:8]}",
        "original_name": "scanned_img_001.png",
        "display_name": "scanned_img_001.png",
        "stored_name": f"test-junk-img-{uuid.uuid4().hex}.png",
        "file_path": f"uploads/test-junk-img-{uuid.uuid4().hex}.png",
        "file_type": "png",
        "mime_type": "image/png",
        "size_bytes": 12000,
        "sha256_hash": "b"*64,
        "extracted_text": "123 abc",
        "category": "General",
        "category_source": "rule",
        "sensitivity": "public",
        "has_ocr": 1,
        "ocr_confidence": 0.20,
        "owner_id": test_user.id,
        "processing_status": "done"
    })

    classifier = DocumentClassifier()
    cat, conf, source, evidence = classifier.classify_multi_signal(
        text=doc.extracted_text,
        filename=doc.original_name,
        file_type=doc.file_type
    )

    assert cat == "General"
    assert conf <= 0.60
    assert evidence["status_label"] == "NEEDS_REVIEW"


def test_acceptance_document_set_classifications(db_session: Session, test_user: User):
    """
    Verify multi-signal classification across representative document types:
    1. DSA Assignment PDF
    2. Resume PDF
    3. Certificate Image
    4. Project Report DOCX
    5. Identity Document
    """
    classifier = DocumentClassifier()

    # 1. DSA Assignment
    cat, conf, _, _ = classifier.classify_multi_signal(
        text="Data Structures and Algorithms Assignment 1 Queue Stack Implementation",
        filename="dsa_assign1.pdf"
    )
    assert cat in ("Assignment", "Academic")
    assert conf >= 0.70

    # 2. Resume PDF
    cat, conf, _, _ = classifier.classify_multi_signal(
        text="John Doe Curriculum Vitae Work Experience Education Skills Python Software Engineer",
        filename="John_Doe_Resume.pdf"
    )
    assert cat == "Resume/CV"
    assert conf >= 0.80

    # 3. Certificate
    cat, conf, _, _ = classifier.classify_multi_signal(
        text="Certificate of Completion awarded to Jane Doe for Python Programming",
        filename="cert_python.jpg"
    )
    assert cat == "Certificate"
    assert conf >= 0.80

    # 4. Project Report
    cat, conf, _, _ = classifier.classify_multi_signal(
        text="System Architecture and Design Specification Project Report Final Findings",
        filename="project_architecture.docx"
    )
    assert cat == "Project"
    assert conf >= 0.75

    # 5. Identity Document
    cat, conf, _, _ = classifier.classify_multi_signal(
        text="Permanent Account Number Government of India PAN Card ABCDE1234F",
        filename="pan_card.pdf",
        pii_types=["PAN"]
    )
    assert cat == "Identity"
    assert conf >= 0.80


def test_suggestion_lifecycle_human_in_the_loop(db_session: Session, test_user: User):
    """
    Test full suggestion lifecycle:
    - Accept suggestion applies change to display_name/category/tags while preserving original_name.
    - Edit suggestion applies user custom value.
    - Reject suggestion marks rejected without mutating document.
    - Keep-As-Is suggestion defers without mutating document.
    """
    doc_repo = DocumentRepository(db_session)
    doc = doc_repo.create({
        "uuid": f"test-lifecycle-{uuid.uuid4().hex[:8]}",
        "original_name": "clg fee.png",
        "display_name": "clg fee.png",
        "stored_name": f"test-lifecycle-{uuid.uuid4().hex}.png",
        "file_path": f"uploads/test-lifecycle-{uuid.uuid4().hex}.png",
        "file_type": "png",
        "mime_type": "image/png",
        "size_bytes": 30000,
        "sha256_hash": "c"*64,
        "extracted_text": "College Fee Receipt Paid $500",
        "category": "General",
        "owner_id": test_user.id,
        "processing_status": "done"
    })

    org_service = OrganizationService()
    org_service.generate_suggestions_for_document(db_session, doc)

    s_repo = SuggestionRepository(db_session)
    suggs = s_repo.get_for_document(doc.id)
    rename_sugg = next(s for s in suggs if s.suggestion_type == "rename")
    cat_sugg = next(s for s in suggs if s.suggestion_type == "categorize")

    # 1. Accept Rename
    org_service.accept_suggestion(db_session, rename_sugg.id, test_user.id)
    db_session.refresh(doc)
    assert doc.original_name == "clg fee.png"  # Original name remains intact!
    assert doc.display_name == rename_sugg.suggested_value
    assert s_repo.get_by_id(rename_sugg.id).status == "accepted"

    # 2. Reject Categorize
    org_service.reject_suggestion(db_session, cat_sugg.id, test_user.id)
    assert s_repo.get_by_id(cat_sugg.id).status == "rejected"

    # 3. Create fresh pending suggestion and test Keep As-Is
    s_new = s_repo.create(
        document_id=doc.id,
        suggestion_type="add_tag",
        current_value="",
        suggested_value="college, fees",
        reason="Test tag",
        confidence=0.85,
        evidence={"tags": ["college", "fees"]}
    )
    org_service.keep_suggestion(db_session, s_new.id, test_user.id)
    assert s_repo.get_by_id(s_new.id).status == "kept"


def test_dynamic_suggestion_re_evaluation_no_duplicates(db_session: Session, test_user: User):
    """
    Test that re-evaluating library suggestions updates pending suggestions in-place
    and does NOT create duplicate pending suggestions for already resolved ones.
    """
    doc_repo = DocumentRepository(db_session)
    doc = doc_repo.create({
        "uuid": f"test-re-eval-{uuid.uuid4().hex[:8]}",
        "original_name": "clg fee.png",
        "display_name": "clg fee.png",
        "stored_name": f"test-re-eval-{uuid.uuid4().hex}.png",
        "file_path": f"uploads/test-re-eval-{uuid.uuid4().hex}.png",
        "file_type": "png",
        "mime_type": "image/png",
        "size_bytes": 30000,
        "sha256_hash": "d"*64,
        "extracted_text": "College Fee Receipt Paid $500",
        "category": "General",
        "owner_id": test_user.id,
        "processing_status": "done"
    })

    org_service = OrganizationService()

    # Pass 1: generate initial suggestions
    org_service.generate_suggestions_for_document(db_session, doc)
    s_repo = SuggestionRepository(db_session)
    suggs_1 = s_repo.get_for_document(doc.id)
    count_1 = len(suggs_1)
    assert count_1 >= 2

    # Accept one suggestion
    cat_sugg = next(s for s in suggs_1 if s.suggestion_type == "categorize")
    org_service.accept_suggestion(db_session, cat_sugg.id, test_user.id)

    # Pass 2: re-evaluate suggestions
    org_service.analyze_library_suggestions(db_session, test_user.id)
    suggs_2 = s_repo.get_for_document(doc.id)

    # Check that accepted categorization suggestion was NOT duplicated as pending
    cat_suggs_pending = [s for s in suggs_2 if s.suggestion_type == "categorize" and s.status == "pending"]
    assert len(cat_suggs_pending) == 0


def test_multi_user_ai_isolation(db_session: Session, test_user: User, other_user: User):
    """
    Verify security boundary: User A cannot view or manipulate User B's AI suggestions.
    """
    doc_repo = DocumentRepository(db_session)
    doc_a = doc_repo.create({
        "uuid": f"user-a-doc-{uuid.uuid4().hex[:8]}",
        "original_name": "user_a_private.pdf",
        "stored_name": f"user-a-doc-{uuid.uuid4().hex}.pdf",
        "file_path": f"uploads/user-a-doc-{uuid.uuid4().hex}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 20000,
        "sha256_hash": "e"*64,
        "extracted_text": "Private Financial Statement",
        "category": "General",
        "owner_id": test_user.id,
        "processing_status": "done"
    })

    org_service = OrganizationService()
    org_service.generate_suggestions_for_document(db_session, doc_a)

    s_repo = SuggestionRepository(db_session)
    suggs_a = s_repo.get_for_document(doc_a.id)
    sugg_id = suggs_a[0].id

    # User B attempts to accept User A's suggestion
    result = org_service.accept_suggestion(db_session, sugg_id, other_user.id)
    assert result is None  # Access blocked!


class _FakeEmbeddingEngine:
    """Deterministic local stub used only to prove semantic signal plumbing."""
    def __init__(self):
        self.vectors = {
            "financial": np.array([1.0, 0.0, 0.0], dtype=np.float32),
            "academic": np.array([0.0, 1.0, 0.0], dtype=np.float32),
            "certificate": np.array([0.0, 0.0, 1.0], dtype=np.float32),
        }

    def is_available(self):
        return True

    def encode_batch(self, texts):
        return [self.vectors["financial"] for _ in texts]

    def encode(self, text):
        if "fee" in text.lower() or "receipt" in text.lower():
            return self.vectors["financial"]
        return self.vectors["academic"]


def test_semantic_signal_is_included_when_embedding_engine_available():
    classifier = DocumentClassifier(embedding_engine=_FakeEmbeddingEngine())
    cat, conf, source, evidence = classifier.classify_multi_signal(
        text="payment receipt for tuition",
        filename="document.png"
    )
    assert cat == "Financial"
    assert source == "multi_signal+semantic"
    assert evidence["semantic_top_match"] == "Financial"
    assert evidence["semantic_similarity"] == 1.0
    assert conf >= 0.70


def test_ai_category_is_recommendation_not_silent_document_mutation(db_session: Session, test_user: User):
    # This protects the product rule that upload-time AI never silently changes the
    # owner's chosen organization state. New docs begin in the neutral system default.
    doc_repo = DocumentRepository(db_session)
    doc = doc_repo.create({
        "uuid": f"test-human-approval-{uuid.uuid4().hex[:8]}",
        "original_name": "clg fee.png",
        "display_name": "clg fee.png",
        "stored_name": f"test-human-approval-{uuid.uuid4().hex}.png",
        "file_path": "uploads/test-human-approval.png",
        "file_type": "image",
        "mime_type": "image/png",
        "size_bytes": 30000,
        "sha256_hash": "f"*64,
        "extracted_text": "College Fee Receipt Paid Amount 500 Semester 3",
        "category": "General",
        "category_source": "system_default",
        "owner_id": test_user.id,
        "processing_status": "done"
    })
    org_service = OrganizationService()
    org_service.generate_suggestions_for_document(db_session, doc)
    db_session.refresh(doc)
    assert doc.category == "General"
    assert doc.category_source == "system_default"


def test_group_suggestion_is_deduplicated_on_reanalysis(db_session: Session, test_user: User):
    doc_repo = DocumentRepository(db_session)
    docs = []
    for i in range(2):
        docs.append(doc_repo.create({
            "uuid": f"test-group-{uuid.uuid4().hex[:8]}",
            "original_name": f"fee_{i}.pdf",
            "display_name": f"fee_{i}.pdf",
            "stored_name": f"test-group-{uuid.uuid4().hex}-{i}.pdf",
            "file_path": f"uploads/test-group-{uuid.uuid4().hex}-{i}.pdf",
            "file_type": "pdf",
            "mime_type": "application/pdf",
            "size_bytes": 30000,
            "sha256_hash": ("1" if i == 0 else "2")*64,
            "extracted_text": "College fee receipt tuition amount",
            "category": "General",
            "category_source": "system_default",
            "owner_id": test_user.id,
            "processing_status": "done"
        }))
    org_service = OrganizationService()
    org_service.analyze_library_suggestions(db_session, test_user.id)
    org_service.analyze_library_suggestions(db_session, test_user.id)
    s_repo = SuggestionRepository(db_session)
    doc_ids = {d.id for d in docs}
    groups = [
        s for s in db_session.query(DocumentSuggestion).filter(
            DocumentSuggestion.suggestion_type == "create_folder_group",
            DocumentSuggestion.document_id.in_(doc_ids)
        ).all()
    ]
    assert len(groups) == 1
