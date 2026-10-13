import pytest
import io
from docx import Document
import json
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.connection import get_db, SessionLocal
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.notification import Notification
from backend.security.password import PasswordManager
from backend.security.jwt_handler import JWTHandler

client = TestClient(app)

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def make_docx(text: str) -> bytes:
    document = Document()
    for paragraph in text.splitlines():
        if paragraph.strip():
            document.add_paragraph(paragraph)
    stream = io.BytesIO()
    document.save(stream)
    return stream.getvalue()


@pytest.fixture
def test_user_session():
    db = SessionLocal()
    user = db.query(User).filter(User.username == "test_four_user").first()
    if not user:
        user = User(
            username="test_four_user",
            email="test_four@example.com",
            password_hash=PasswordManager.hash_password("Password123!"),
            role="user",
            is_active=1
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    
    token, _ = JWTHandler.create_access_token(user.id, user.role)
    headers = {"Authorization": f"Bearer {token}"}
    yield user, headers, db
    db.close()


def test_duplicate_alerts_pipeline(test_user_session):
    user, headers, db = test_user_session

    text_content = (
        "IntelliDocs Smart Document Management System provides offline AI document "
        "classification, hybrid full-text search, multi-level security scanning, "
        "and duplicate detection algorithms across all local workspace repositories."
    )

    # 1. Upload Doc A
    resp_a = client.post(
        "/documents/upload",
        files={"file": ("invoice_june.docx", make_docx(text_content), DOCX_MIME)},
        headers=headers
    )
    assert resp_a.status_code == 201
    doc_a_data = resp_a.json()
    assert doc_a_data["uuid"] is not None

    # 2. Upload Doc B (near duplicate ~92% similarity)
    text_content_b = (
        "IntelliDocs Smart Document Management System provides offline AI document "
        "classification, hybrid full-text search, multi-level security scanning, "
        "and duplicate detection algorithms across local workspace repositories."
    )
    resp_b = client.post(
        "/documents/upload",
        files={"file": ("invoice_june_copy.docx", make_docx(text_content_b), DOCX_MIME)},
        headers=headers
    )
    assert resp_b.status_code == 201
    doc_b_data = resp_b.json()
    assert doc_b_data["uuid"] is not None

    # 3. Check /duplicates/alerts endpoint
    alerts_resp = client.get("/duplicates/alerts", headers=headers)
    assert alerts_resp.status_code == 200
    alerts_data = alerts_resp.json()
    assert alerts_data["alert_count"] >= 1
    
    found_alert = any(
        (a["document_uuid"] == doc_a_data["uuid"] or a["candidate_uuid"] == doc_a_data["uuid"])
        and (a["document_uuid"] == doc_b_data["uuid"] or a["candidate_uuid"] == doc_b_data["uuid"])
        for a in alerts_data["alerts"]
    )
    assert found_alert, "Duplicate alert was not generated for near-duplicate documents"


def test_ai_summary_generation_and_persistence(test_user_session):
    user, headers, db = test_user_session

    doc_text = (
        "Artificial Intelligence in document processing allows automated categorization and metadata extraction. "
        "IntelliDocs uses local NLP algorithms and text summarization to produce concise previews of large documents. "
        "Security features such as static malware analysis and quarantine management protect user data."
    )

    resp = client.post(
        "/documents/upload",
        files={"file": ("research_paper.docx", make_docx(doc_text), DOCX_MIME)},
        headers=headers
    )
    assert resp.status_code == 201
    doc_uuid = resp.json()["uuid"]

    # Trigger explicit POST /documents/{uuid}/summarize
    sum_resp = client.post(f"/documents/{doc_uuid}/summary", headers=headers)
    assert sum_resp.status_code == 200
    sum_data = sum_resp.json()
    assert sum_data["summary"] is not None
    assert len(sum_data["summary"]) > 10
    assert "document" in sum_data["summary"].lower() or "intelli" in sum_data["summary"].lower() or "artificial" in sum_data["summary"].lower()

    # Verify persistence after fetch
    detail_resp = client.get(f"/documents/{doc_uuid}", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["summary"] == sum_data["summary"]


def test_notifications_unread_read_flow(test_user_session):
    user, headers, db = test_user_session

    # Fetch initial notifications
    list_resp = client.get("/notifications", headers=headers)
    assert list_resp.status_code == 200
    initial_notifs = list_resp.json()
    assert isinstance(initial_notifs, list)

    # Mark all read
    read_all_resp = client.post("/notifications/read-all", headers=headers)
    assert read_all_resp.status_code == 200

    unread_resp = client.get("/notifications?unread_only=true", headers=headers)
    assert unread_resp.status_code == 200
    assert len(unread_resp.json()) == 0


def test_security_scan_safe_ux_endpoint(test_user_session):
    user, headers, db = test_user_session

    # Security assessment is part of the supported upload flow.
    clean_text = (
        "IntelliDocs security verification document. "
        "This harmless document checks security assessment results "
        "and the user-facing evidence returned by the upload endpoint."
    )
    response = client.post(
        "/documents/upload",
        files={"file": ("clean_report.docx", make_docx(clean_text), DOCX_MIME)},
        headers=headers,
    )

    assert response.status_code == 201, response.text
    data = response.json()
    assert data.get("uuid"), data

    assessment = data.get("security_assessment")
    assert isinstance(assessment, dict), data
    assert assessment.get("verdict") == "SAFE", assessment
    assert assessment.get("risk_score", 100) < 30, assessment
    assert assessment.get("risk_level") == "LOW RISK", assessment
    assert assessment.get("scanner_status") in {
        "AVAILABLE", "UNAVAILABLE", "PARTIAL"
    }, assessment
