from fastapi.testclient import TestClient
import pytest
import uuid

from sqlalchemy.orm import Session

from backend.main import app
from backend.database.connection import SessionLocal, engine, Base
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.security.password import PasswordManager


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
    suffix = uuid.uuid4().hex[:8]
    username = f"{prefix}_{suffix}"
    email = f"{username}@example.com"

    user = repo.create_user(
        username=username,
        email=email,
        password_hash=PasswordManager.hash_password("Password123!"),
    )
    return user


def _get_auth_headers(username: str):
    res = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "Password123!",
        },
    )
    assert res.status_code == 200, res.text
    return {
        "Authorization": f"Bearer {res.json()['access_token']}"
    }


def _activate_received_share(headers, share_id: int):
    report = client.get(f"/shares/direct/{share_id}/security-report", headers=headers)
    assert report.status_code == 200, report.text
    report_data = report.json()
    result = client.post(
        f"/shares/direct/{share_id}/activate", headers=headers,
        json={"assessment_id": report_data["assessment_id"],
              "acknowledge_limited": bool(report_data.get("limited_checks_ack_required"))},
    )
    assert result.status_code == 200, result.text
    return result.json()


MINIMAL_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"00000000115 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\n"
    b"startxref\n190\n%%EOF"
)


def _upload_document(headers):
    res = client.post(
        "/documents/upload",
        files={
            "file": (
                "share_key_integration.pdf",
                MINIMAL_PDF,
                "application/pdf",
            )
        },
        headers=headers,
    )
    assert res.status_code == 201, res.text
    return res.json()["uuid"]


def test_share_key_complete_http_lifecycle(db_session: Session):
    owner = _create_test_user(db_session, "sk_api_owner")
    recipient = _create_test_user(db_session, "sk_api_recipient")
    attacker = _create_test_user(db_session, "sk_api_attacker")

    owner_headers = _get_auth_headers(owner.username)
    recipient_headers = _get_auth_headers(recipient.username)
    attacker_headers = _get_auth_headers(attacker.username)

    # ------------------------------------------------------------
    # 1. Owner uploads document
    # ------------------------------------------------------------
    doc_uuid = _upload_document(owner_headers)

    # ------------------------------------------------------------
    # 2. Owner creates protected direct share
    # ------------------------------------------------------------
    create_res = client.post(
        f"/documents/{doc_uuid}/shares",
        json={
            "target_users": [recipient.username],
            "permission": "READ",
            "protect_with_key": True,
        },
        headers=owner_headers,
    )

    assert create_res.status_code == 201, create_res.text

    created = create_res.json()
    assert len(created) == 1

    share = created[0]
    share_id = share["id"]
    raw_key = share.get("share_key")

    assert share["share_key_required"] is True
    assert share["share_key_verified"] is False
    assert isinstance(raw_key, str)
    assert len(raw_key) >= 20

    # Raw key must not be the stored hash.
    db_share = ShareRepository(db_session).get_direct_share_by_id(share_id)
    assert db_share is not None
    assert db_share.share_key_required == 1
    assert db_share.share_key_hash
    assert db_share.share_key_hash != raw_key
    assert db_share.share_key_verified_at is None

    # ------------------------------------------------------------
    # 3. Recipient receives share metadata, but raw key isn't
    # returned by list endpoints
    # ------------------------------------------------------------
    received_res = client.get(
        "/shares/received",
        headers=recipient_headers,
    )

    assert received_res.status_code == 200, received_res.text

    received_match = [
        item
        for item in received_res.json()
        if item["id"] == share_id
    ]

    assert len(received_match) == 1
    assert received_match[0]["share_key_required"] is True
    assert received_match[0]["share_key_verified"] is False
    assert received_match[0].get("share_key") is None

    owner_list_res = client.get(
        f"/documents/{doc_uuid}/shares",
        headers=owner_headers,
    )

    assert owner_list_res.status_code == 200, owner_list_res.text

    owner_match = [
        item
        for item in owner_list_res.json()
        if item["id"] == share_id
    ]

    assert len(owner_match) == 1
    assert owner_match[0].get("share_key") is None

    # ------------------------------------------------------------
    # 4. Recipient is blocked before verification
    # ------------------------------------------------------------
    before_verify = client.get(
        f"/documents/{doc_uuid}",
        headers=recipient_headers,
    )

    assert before_verify.status_code == 404, before_verify.text

    status_before = client.get(
        f"/documents/{doc_uuid}/shares/{share_id}/key-status",
        headers=recipient_headers,
    )

    assert status_before.status_code == 200, status_before.text
    assert status_before.json()["required"] is True
    assert status_before.json()["verified"] is False

    # ------------------------------------------------------------
    # 5. Wrong key rejected
    # ------------------------------------------------------------
    wrong_key = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": raw_key + "-wrong"},
        headers=recipient_headers,
    )

    assert wrong_key.status_code == 403, wrong_key.text

    # ------------------------------------------------------------
    # 6. Attacker cannot verify recipient's share
    # ------------------------------------------------------------
    attacker_verify = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": raw_key},
        headers=attacker_headers,
    )

    assert attacker_verify.status_code == 403, attacker_verify.text

    # ------------------------------------------------------------
    # 7. Correct key verifies
    # ------------------------------------------------------------
    verify_res = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": raw_key},
        headers=recipient_headers,
    )

    assert verify_res.status_code == 200, verify_res.text
    assert verify_res.json()["verified"] is True

    status_after = client.get(
        f"/documents/{doc_uuid}/shares/{share_id}/key-status",
        headers=recipient_headers,
    )

    assert status_after.status_code == 200
    assert status_after.json()["verified"] is True

    # Key verification is only one gate; the recipient remains pending until the
    # source assessment is reviewed and this specific share is activated.
    after_verify = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
    assert after_verify.status_code == 404, after_verify.text
    _activate_received_share(recipient_headers, share_id)
    after_activation = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
    assert after_activation.status_code == 200, after_activation.text

    # ------------------------------------------------------------
    # 8. Attacker cannot rotate the key
    # ------------------------------------------------------------
    attacker_rotate = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/rotate-key",
        headers=attacker_headers,
    )

    assert attacker_rotate.status_code == 403, attacker_rotate.text

    # ------------------------------------------------------------
    # 9. Owner rotates key
    # ------------------------------------------------------------
    rotate_res = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/rotate-key",
        headers=owner_headers,
    )

    assert rotate_res.status_code == 200, rotate_res.text

    rotated = rotate_res.json()
    new_key = rotated.get("share_key")

    assert rotated["required"] is True
    assert rotated["verified"] is False
    assert isinstance(new_key, str)
    assert len(new_key) >= 20
    assert new_key != raw_key

    # Rotation must immediately remove the previous verification.
    after_rotation_status = client.get(
        f"/documents/{doc_uuid}/shares/{share_id}/key-status",
        headers=recipient_headers,
    )

    assert after_rotation_status.status_code == 200
    assert after_rotation_status.json()["verified"] is False

    # Old key must no longer work.
    old_key_res = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": raw_key},
        headers=recipient_headers,
    )

    assert old_key_res.status_code == 403, old_key_res.text

    # Access remains blocked until the new key is verified.
    blocked_after_rotation = client.get(
        f"/documents/{doc_uuid}",
        headers=recipient_headers,
    )

    assert blocked_after_rotation.status_code == 404, blocked_after_rotation.text

    # ------------------------------------------------------------
    # 10. New key works
    # ------------------------------------------------------------
    new_key_res = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": new_key},
        headers=recipient_headers,
    )

    assert new_key_res.status_code == 200, new_key_res.text
    assert new_key_res.json()["verified"] is True

    still_pending_after_new_key = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
    assert still_pending_after_new_key.status_code == 404, still_pending_after_new_key.text
    _activate_received_share(recipient_headers, share_id)
    restored_access = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
    assert restored_access.status_code == 200, restored_access.text

    # ------------------------------------------------------------
    # 11. Owner revokes share
    # ------------------------------------------------------------
    revoke_res = client.delete(
        f"/documents/{doc_uuid}/shares/{share_id}",
        headers=owner_headers,
    )

    assert revoke_res.status_code == 200, revoke_res.text

    # Revoked share must disappear from effective access.
    revoked_access = client.get(
        f"/documents/{doc_uuid}",
        headers=recipient_headers,
    )

    assert revoked_access.status_code == 404, revoked_access.text

    # Revoked share cannot be verified again.
    verify_revoked = client.post(
        f"/documents/{doc_uuid}/shares/{share_id}/verify-key",
        json={"key": new_key},
        headers=recipient_headers,
    )

    assert verify_revoked.status_code == 404, verify_revoked.text

    # Verify persisted revoke state using a fresh SQLAlchemy session.
    # The original test session may still hold a previously loaded ORM
    # object whose fields were changed by the API in another session.
    fresh_db = SessionLocal()
    try:
        db_share = ShareRepository(fresh_db).get_direct_share_by_id(share_id)
        assert db_share is not None
        assert db_share.active == 0
        assert db_share.share_key_verified_at is None
    finally:
        fresh_db.close()


def test_unprotected_direct_share_keeps_existing_behavior():
    """
    Regression check: an unprotected direct share still skips Share Key
    verification, but it requires the independent assessment activation step.
    """
    db = SessionLocal()
    try:
        owner = _create_test_user(db, "sk_normal_owner")
        recipient = _create_test_user(db, "sk_normal_recipient")

        owner_headers = _get_auth_headers(owner.username)
        recipient_headers = _get_auth_headers(recipient.username)

        doc_uuid = _upload_document(owner_headers)

        share_res = client.post(
            f"/documents/{doc_uuid}/shares",
            json={
                "target_users": [recipient.username],
                "permission": "READ",
                "protect_with_key": False,
            },
            headers=owner_headers,
        )

        assert share_res.status_code == 201, share_res.text

        data = share_res.json()[0]

        assert data["share_key_required"] is False
        assert data["share_key_verified"] is True
        assert data.get("share_key") is None

        access_res = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
        assert access_res.status_code == 404, access_res.text
        _activate_received_share(recipient_headers, data["id"])
        access_after_activation = client.get(f"/documents/{doc_uuid}", headers=recipient_headers)
        assert access_after_activation.status_code == 200, access_after_activation.text

    finally:
        db.close()
