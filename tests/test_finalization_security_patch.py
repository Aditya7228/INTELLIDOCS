"""Targeted regression tests for pre-deployment isolation and upload safeguards."""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database.connection import Base, SessionLocal, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.security.password import PasswordManager
from backend.api.deps import search_service_instance
from backend.config import settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def _ensure_schema():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _make_user(db: Session, prefix: str):
    suffix = uuid.uuid4().hex[:8]
    username = f"{prefix}_{suffix}"
    return UserRepository(db).create_user(
        username=username,
        email=f"{username}@example.com",
        password_hash=PasswordManager.hash_password("StrongPass123!"),
    )


def _auth(username: str):
    response = client.post(
        "/auth/login", json={"username": username, "password": "StrongPass123!"}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _make_doc(db: Session, owner_id: int, filename: str):
    token = uuid.uuid4().hex
    return DocumentRepository(db).create({
        "uuid": token,
        "original_name": filename,
        "display_name": filename,
        "stored_name": f"{token}.txt",
        "file_path": f"uploads/{token}.txt",
        "file_type": "txt",
        "mime_type": "text/plain",
        "size_bytes": 20,
        "sha256_hash": uuid.uuid4().hex + uuid.uuid4().hex,
        "owner_id": owner_id,
        "processing_status": "done",
        "extracted_text": "",
    })


def test_autocomplete_does_not_disclose_another_users_tokens(db_session: Session):
    owner = _make_user(db_session, "token_owner")
    unrelated = _make_user(db_session, "token_unrelated")
    doc = _make_doc(db_session, owner.id, "private-notes.txt")
    secret_token = "orchidconfidentialtoken"
    search_service_instance.index_document(doc.id, f"{secret_token} owner only")

    outsider_headers = _auth(unrelated.username)
    leaked = client.get(
        "/search/suggest", params={"prefix": "orchid"}, headers=outsider_headers
    )
    assert leaked.status_code == 200, leaked.text
    assert secret_token not in leaked.json()["suggestions"]

    owner_headers = _auth(owner.username)
    visible = client.get(
        "/search/suggest", params={"prefix": "orchid"}, headers=owner_headers
    )
    assert visible.status_code == 200, visible.text
    assert secret_token in visible.json()["suggestions"]


def test_duplicate_decision_rejects_other_users_document(db_session: Session):
    first_user = _make_user(db_session, "dup_owner")
    second_user = _make_user(db_session, "dup_other")
    own_doc = _make_doc(db_session, first_user.id, "own.txt")
    private_doc = _make_doc(db_session, second_user.id, "private.txt")

    response = client.post(
        "/duplicates/decide",
        headers=_auth(first_user.username),
        json={
            "new_doc_uuid": own_doc.uuid,
            "existing_doc_uuid": private_doc.uuid,
            "action": "keep_both",
        },
    )
    assert response.status_code == 404, response.text


def test_upload_size_limit_applies_before_security_scanning(monkeypatch):
    user_db = SessionLocal()
    try:
        user = _make_user(user_db, "upload_limit")
        headers = _auth(user.username)
    finally:
        user_db.close()

    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 1)
    oversized = b"x" * (1024 * 1024 + 1)
    response = client.post(
        "/documents/upload",
        headers=headers,
        files={"file": ("oversized.txt", oversized, "text/plain")},
    )
    assert response.status_code == 413, response.text
