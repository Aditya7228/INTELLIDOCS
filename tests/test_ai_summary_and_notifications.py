import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.main import app
from backend.database.connection import SessionLocal, Base, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.notification_repo import NotificationRepository
from backend.security.password import PasswordManager
from backend.ai.summarizer import Summarizer

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _create_test_user(db: Session, prefix: str):
    repo = UserRepository(db)
    suffix = uuid.uuid4().hex[:6]
    username = f"{prefix}_{suffix}"
    email = f"{username}@example.com"
    pwd_hash = PasswordManager.hash_password("Password123!")
    user = repo.create_user(username=username, email=email, password_hash=pwd_hash)
    return user


def _get_auth_headers(username: str, password: str = "Password123!"):
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _create_test_doc(db: Session, owner_id: int, original_name: str, extracted_text: str = ""):
    doc_repo = DocumentRepository(db)
    doc_uuid = str(uuid.uuid4())
    stored_name = f"{doc_uuid}_{original_name}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": original_name,
        "stored_name": stored_name,
        "file_path": f"/storage/{stored_name}",
        "display_name": original_name,
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 2048,
        "sha256_hash": uuid.uuid4().hex,
        "owner_id": owner_id,
        "extracted_text": extracted_text,
        "category": "General"
    })
    return doc


def test_summarizer_extractive_and_topics():
    summarizer = Summarizer()
    text = (
        "IntelliDocs is an advanced document processing platform. "
        "It provides automated AI classification, duplicate detection, and security controls. "
        "Users can upload PDF and DOCX files for instant search indexing. "
        "The system enforces strict access control policies across all user documents."
    )
    summary = summarizer.summarize(text)
    assert summary is not None
    assert len(summary) > 20

    topics = summarizer.extract_key_topics(text, filename="IntelliDocs_Overview.pdf", category="Technology")
    assert isinstance(topics, list)
    assert len(topics) >= 1


def test_summarizer_empty_text_handling():
    summarizer = Summarizer()
    summary = summarizer.summarize("")
    assert summary == "No extractable text content available for summarization."

    topics = summarizer.extract_key_topics("", filename="empty.pdf", category="General")
    assert topics == [] or isinstance(topics, list)


def test_document_detail_summary_and_key_topics_endpoint(db_session: Session):
    user = _create_test_user(db_session, "summary_user")
    text = (
        "College Tuition Fee Receipt for 2026 Academic Year. "
        "Department of Computer Science and Engineering. "
        "Paid amount INR 45,000 via online bank transfer. "
        "Receipt registration status confirmed."
    )
    doc = _create_test_doc(db_session, user.id, "clg_fee_receipt.pdf", extracted_text=text)

    headers = _get_auth_headers(user.username)
    res = client.get(f"/documents/{doc.uuid}", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "summary" in data
    assert data["summary"] is not None
    assert "key_topics" in data
    assert isinstance(data["key_topics"], list)
    assert len(data["key_topics"]) >= 1


def test_notifications_api_and_document_uuid(db_session: Session):
    user = _create_test_user(db_session, "notif_user")
    doc = _create_test_doc(db_session, user.id, "notif_doc.pdf", extracted_text="Sample notification text")

    notif_repo = NotificationRepository(db_session)
    n = notif_repo.create(
        user_id=user.id,
        event_type="PROCESSING_COMPLETE",
        title="Processing Complete",
        message="Document processed",
        document_id=doc.id
    )

    headers = _get_auth_headers(user.username)
    res = client.get("/notifications", headers=headers)
    assert res.status_code == 200
    notifs = res.json()
    assert len(notifs) >= 1
    found = next((item for item in notifs if item["id"] == n.id), None)
    assert found is not None
    assert found["document_uuid"] == doc.uuid
    assert found["is_read"] == 0

    # Mark as read
    res_read = client.post(f"/notifications/{n.id}/read", headers=headers)
    assert res_read.status_code == 200

    # Mark all read
    res_all_read = client.post("/notifications/read-all", headers=headers)
    assert res_all_read.status_code == 200

    res_unread = client.get("/notifications?unread_only=true", headers=headers)
    assert res_unread.status_code == 200
    assert len(res_unread.json()) == 0


def test_multi_user_notification_isolation(db_session: Session):
    user_a = _create_test_user(db_session, "notif_user_a")
    user_b = _create_test_user(db_session, "notif_user_b")

    notif_repo = NotificationRepository(db_session)
    notif_repo.create(user_id=user_a.id, event_type="SHARE_GRANTED", title="Private A", message="Owner A notification")

    headers_b = _get_auth_headers(user_b.username)
    res_b = client.get("/notifications", headers=headers_b)
    assert res_b.status_code == 200
    b_notifs = res_b.json()
    assert not any(n["title"] == "Private A" for n in b_notifs), "User B must not see User A's notifications"
