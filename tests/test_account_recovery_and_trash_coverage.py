"""Additional regression coverage for account recovery, email OTP, and Trash lifecycle.

These tests patch outbound email only; they never send real mail and never modify
application source. Run from project root with the project's virtual environment.
"""
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import backend.api.auth as auth_api
from backend.config import settings
from backend.database.connection import Base, engine, SessionLocal
from backend.main import app
from backend.models.document import DocumentModel
from backend.models.email_change_otp import EmailChangeOTP
from backend.models.password_reset_token import PasswordResetToken
from backend.models.session_token import Session as SessionModel

client = TestClient(app)

MAIL_CONFIG = {
    "host": "smtp.example.com",
    "port": 587,
    "user": "test-user",
    "password": "test-password",
    "sender": "noreply@example.com",
    "public_url": "http://localhost:8000",
}
PASSWORD = "StrongPassword123!"


@pytest.fixture(autouse=True)
def ensure_tables():
    Base.metadata.create_all(bind=engine)
    yield


def create_user(prefix="cov"):
    username = f"{prefix}_{uuid.uuid4().hex[:10]}"
    email = f"{username}@example.com"
    response = client.post("/auth/register", json={
        "username": username,
        "email": email,
        "password": PASSWORD,
    })
    assert response.status_code == 201, response.text
    return {"id": response.json()["id"], "username": username, "email": email}


def auth_headers(username, password=PASSWORD):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}, response.json()


def db_count(model, **filters):
    db = SessionLocal()
    try:
        query = db.query(model)
        if filters:
            query = query.filter_by(**filters)
        return query.count()
    finally:
        db.close()


def test_password_reset_is_generic_single_use_and_revokes_old_session(monkeypatch):
    user = create_user("resetcov")
    headers, login_data = auth_headers(user["username"])
    mailed_urls = []
    monkeypatch.setattr(auth_api, "_password_reset_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(auth_api, "_password_reset_smtp_config", lambda: dict(MAIL_CONFIG))
    monkeypatch.setattr(
        auth_api,
        "_send_password_reset_email",
        lambda recipient, reset_url, config: mailed_urls.append((recipient, reset_url)),
    )

    unknown = client.post("/auth/forgot-password", json={"email": f"absent-{uuid.uuid4().hex[:8]}@example.com"})
    known = client.post("/auth/forgot-password", json={"email": user["email"]})
    assert unknown.status_code == known.status_code == 200
    assert unknown.json() == known.json(), "Forgot-password must not reveal whether an account exists."
    assert len(mailed_urls) == 1
    assert mailed_urls[0][0].lower() == user["email"].lower()

    reset_token = parse_qs(urlparse(mailed_urls[0][1]).query)["reset_token"][0]
    new_password = "AnotherStrongPassword456!"
    reset = client.post("/auth/reset-password", json={"token": reset_token, "new_password": new_password})
    assert reset.status_code == 200, reset.text

    # Reset invalidates all existing sessions and the one-time reset token.
    old_session = client.get("/auth/me", headers=headers)
    assert old_session.status_code == 401
    old_login = client.post("/auth/login", json={"username": user["username"], "password": PASSWORD})
    assert old_login.status_code == 401
    new_login = client.post("/auth/login", json={"username": user["username"], "password": new_password})
    assert new_login.status_code == 200, new_login.text
    reused = client.post("/auth/reset-password", json={"token": reset_token, "new_password": PASSWORD})
    assert reused.status_code == 400


def test_password_reset_rejects_invalid_and_expired_tokens(monkeypatch):
    user = create_user("expiredcov")
    mailed_urls = []
    monkeypatch.setattr(auth_api, "_password_reset_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(auth_api, "_password_reset_smtp_config", lambda: dict(MAIL_CONFIG))
    monkeypatch.setattr(
        auth_api,
        "_send_password_reset_email",
        lambda recipient, reset_url, config: mailed_urls.append(reset_url),
    )
    assert client.post("/auth/forgot-password", json={"email": user["email"]}).status_code == 200
    reset_token = parse_qs(urlparse(mailed_urls[0]).query)["reset_token"][0]
    token_hash = hashlib.sha256(reset_token.encode("utf-8")).hexdigest()

    db = SessionLocal()
    try:
        record = db.query(PasswordResetToken).filter_by(token_hash=token_hash).one()
        record.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        db.commit()
    finally:
        db.close()

    expired = client.post("/auth/reset-password", json={"token": reset_token, "new_password": "AnotherStrongPassword456!"})
    invalid = client.post("/auth/reset-password", json={"token": "invalid-token-" + uuid.uuid4().hex, "new_password": "AnotherStrongPassword456!"})
    assert expired.status_code == 400
    assert invalid.status_code == 400
    old_login = client.post("/auth/login", json={"username": user["username"], "password": PASSWORD})
    assert old_login.status_code == 200, "Rejected token must not change the password."


def test_email_change_requires_password_valid_otp_and_single_use(monkeypatch):
    monkeypatch.setenv("AUTH_OTP_PEPPER", "coverage-test-pepper-do-not-use-in-production")
    monkeypatch.setattr(auth_api, "_password_reset_smtp_config", lambda: dict(MAIL_CONFIG))
    mailed_codes = []
    monkeypatch.setattr(
        auth_api,
        "_send_email_change_otp",
        lambda recipient, code, config: mailed_codes.append((recipient, code)),
    )
    user = create_user("emailcov")
    other = create_user("emailtaken")
    headers, _ = auth_headers(user["username"])

    wrong_password = client.post("/auth/email-change/request", headers=headers, json={
        "current_password": "WrongPassword123!",
        "new_email": f"new-{uuid.uuid4().hex[:8]}@example.com",
    })
    assert wrong_password.status_code == 400

    duplicate_email = client.post("/auth/email-change/request", headers=headers, json={
        "current_password": PASSWORD,
        "new_email": other["email"],
    })
    assert duplicate_email.status_code == 409

    target_email = f"new-{uuid.uuid4().hex[:10]}@example.com"
    request_code = client.post("/auth/email-change/request", headers=headers, json={
        "current_password": PASSWORD,
        "new_email": target_email,
    })
    assert request_code.status_code == 200, request_code.text
    assert mailed_codes and mailed_codes[0][0].lower() == target_email.lower()
    otp = mailed_codes[0][1]
    incorrect_otp = "000000" if otp != "000000" else "000001"

    bad_verify = client.post("/auth/email-change/verify", headers=headers, json={
        "new_email": target_email,
        "otp": incorrect_otp,
    })
    assert bad_verify.status_code == 400
    assert client.get("/auth/me", headers=headers).json()["email"].lower() == user["email"].lower()

    good_verify = client.post("/auth/email-change/verify", headers=headers, json={
        "new_email": target_email,
        "otp": otp,
    })
    assert good_verify.status_code == 200, good_verify.text
    assert good_verify.json()["email"].lower() == target_email.lower()
    assert client.get("/auth/me", headers=headers).json()["email"].lower() == target_email.lower()

    reuse = client.post("/auth/email-change/verify", headers=headers, json={
        "new_email": target_email,
        "otp": otp,
    })
    assert reuse.status_code == 400


def test_missing_email_configuration_fails_safely_without_creating_tokens(monkeypatch):
    user = create_user("noconfigcov")
    headers, _ = auth_headers(user["username"])
    monkeypatch.setattr(auth_api, "_password_reset_ip_allowed", lambda _ip: True)
    monkeypatch.setattr(auth_api, "_password_reset_smtp_config", lambda: None)
    before_reset = db_count(PasswordResetToken, user_id=user["id"])
    before_otp = db_count(EmailChangeOTP, user_id=user["id"])

    forgotten = client.post("/auth/forgot-password", json={"email": user["email"]})
    email_change = client.post("/auth/email-change/request", headers=headers, json={
        "current_password": PASSWORD,
        "new_email": f"no-smtp-{uuid.uuid4().hex[:8]}@example.com",
    })

    assert forgotten.status_code == 200
    assert db_count(PasswordResetToken, user_id=user["id"]) == before_reset
    assert email_change.status_code == 503
    assert db_count(EmailChangeOTP, user_id=user["id"]) == before_otp


def _make_document(owner_id, name_prefix="trashcov"):
    from datetime import datetime, timezone
    token = uuid.uuid4().hex
    stored_name = f"{name_prefix}-{token}.pdf"
    doc = DocumentModel(
        uuid=f"{name_prefix}-{token}",
        original_name=f"{name_prefix}-{token}.pdf",
        stored_name=stored_name,
        file_path=f"uploads/{stored_name}",
        file_type="pdf",
        mime_type="application/pdf",
        size_bytes=24,
        sha256_hash=hashlib.sha256(token.encode()).hexdigest(),
        owner_id=owner_id,
        sensitivity="public",
        has_ocr=0,
        processing_status="done",
        uploaded_at=datetime.now(timezone.utc).isoformat(),
        is_deleted=0,
    )
    db = SessionLocal()
    try:
        db.add(doc)
        db.commit()
        db.refresh(doc)
        return doc.uuid, doc.stored_name
    finally:
        db.close()


def test_trash_delete_restore_purge_and_owner_isolation():
    owner = create_user("trashowner")
    other = create_user("trashother")
    owner_headers, _ = auth_headers(owner["username"])
    other_headers, _ = auth_headers(other["username"])
    doc_uuid, stored_name = _make_document(owner["id"])
    uploads = Path(settings.STORAGE_DIR).resolve() / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    physical_file = uploads / stored_name
    physical_file.write_bytes(b"intellidocs trash lifecycle test file")

    try:
        deleted = client.delete(f"/documents/{doc_uuid}", headers=owner_headers)
        assert deleted.status_code == 200, deleted.text
        owner_trash = client.get("/trash", headers=owner_headers)
        assert owner_trash.status_code == 200
        assert any(row["uuid"] == doc_uuid for row in owner_trash.json())
        assert client.get(f"/documents/{doc_uuid}", headers=owner_headers).status_code == 404

        # Trash is owner-scoped; another account cannot restore or purge it.
        assert all(row["uuid"] != doc_uuid for row in client.get("/trash", headers=other_headers).json())
        assert client.post(f"/trash/{doc_uuid}/restore", headers=other_headers).status_code == 404
        assert client.delete(f"/trash/{doc_uuid}/purge", headers=other_headers).status_code == 404

        restored = client.post(f"/trash/{doc_uuid}/restore", headers=owner_headers)
        assert restored.status_code == 200, restored.text
        assert all(row["uuid"] != doc_uuid for row in client.get("/trash", headers=owner_headers).json())
        assert client.get(f"/documents/{doc_uuid}", headers=owner_headers).status_code == 200

        assert client.delete(f"/documents/{doc_uuid}", headers=owner_headers).status_code == 200
        purged = client.delete(f"/trash/{doc_uuid}/purge", headers=owner_headers)
        assert purged.status_code == 200, purged.text
        assert not physical_file.exists(), "Purge should remove the stored file when present."
        assert all(row["uuid"] != doc_uuid for row in client.get("/trash", headers=owner_headers).json())
        assert client.get(f"/documents/{doc_uuid}", headers=owner_headers).status_code == 404
    finally:
        try:
            if physical_file.exists():
                physical_file.unlink()
        except Exception:
            pass
