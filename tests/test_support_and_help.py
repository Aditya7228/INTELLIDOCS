import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.main import app
from backend.database.connection import get_db, engine, Base
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.security.password import PasswordManager

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def _create_user(db: Session, prefix: str):
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


def test_submit_support_ticket_success():
    db = next(get_db())
    user = _create_user(db, "support_user_1")
    headers = _get_auth_headers(user.username)

    payload = {
        "issue_type": "upload",
        "subject": "PDF OCR processing delay",
        "message": "When uploading a 15-page scanned contract, OCR processing took longer than expected."
    }

    res = client.post("/support/tickets", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["id"] > 0
    assert data["user_id"] == user.id
    assert data["issue_type"] == "upload"
    assert data["subject"] == payload["subject"]
    assert data["status"] == "open"


def test_support_ticket_validation_failures():
    db = next(get_db())
    user = _create_user(db, "support_val_user")
    headers = _get_auth_headers(user.username)

    # Invalid issue type
    res = client.post("/support/tickets", json={
        "issue_type": "invalid_category",
        "subject": "Valid Subject Here",
        "message": "Valid detailed message content for testing."
    }, headers=headers)
    assert res.status_code == 422

    # Subject too short
    res = client.post("/support/tickets", json={
        "issue_type": "general",
        "subject": "Hi",
        "message": "Valid detailed message content for testing."
    }, headers=headers)
    assert res.status_code == 422

    # Message too short
    res = client.post("/support/tickets", json={
        "issue_type": "general",
        "subject": "Valid Subject Here",
        "message": "Short"
    }, headers=headers)
    assert res.status_code == 422


def test_support_ticket_unauthenticated():
    res = client.post("/support/tickets", json={
        "issue_type": "general",
        "subject": "Test Unauth Subject",
        "message": "Testing unauthenticated request handling."
    })
    assert res.status_code == 401

    res = client.get("/support/tickets")
    assert res.status_code == 401


def test_support_ticket_user_isolation():
    db = next(get_db())
    user_a = _create_user(db, "support_user_a")
    user_b = _create_user(db, "support_user_b")

    headers_a = _get_auth_headers(user_a.username)
    headers_b = _get_auth_headers(user_b.username)

    # User A submits a ticket
    res_a = client.post("/support/tickets", json={
        "issue_type": "sharing",
        "subject": "User A Share Question",
        "message": "User A is asking about group document permissions."
    }, headers=headers_a)
    assert res_a.status_code == 201

    # User B submits a ticket
    res_b = client.post("/support/tickets", json={
        "issue_type": "access_lock",
        "subject": "User B Lock Question",
        "message": "User B is asking about access lock password hashes."
    }, headers=headers_b)
    assert res_b.status_code == 201

    # User A listing tickets only sees User A's ticket
    list_a = client.get("/support/tickets", headers=headers_a).json()
    assert len(list_a) == 1
    assert list_a[0]["subject"] == "User A Share Question"
    assert list_a[0]["user_id"] == user_a.id

    # User B listing tickets only sees User B's ticket
    list_b = client.get("/support/tickets", headers=headers_b).json()
    assert len(list_b) == 1
    assert list_b[0]["subject"] == "User B Lock Question"
    assert list_b[0]["user_id"] == user_b.id
