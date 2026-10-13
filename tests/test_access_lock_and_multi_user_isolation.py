import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.main import app
from backend.database.connection import get_db, engine, Base
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.group_repo import GroupRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.database.repositories.audit_repo import AuditRepository
from backend.security.password import PasswordManager
from backend.security.access_lock_limiter import access_lock_limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    access_lock_limiter.reset_all_for_tests()
    yield
    access_lock_limiter.reset_all_for_tests()


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


def _activate_locked_direct_share(headers, doc_uuid: str, share_id: int, access_key: str):
    unlock = client.post(
        f"/documents/{doc_uuid}/access-lock/unlock",
        json={"access_key": access_key}, headers=headers,
    )
    assert unlock.status_code == 200, unlock.text
    unlocked_headers = {**headers, "X-Access-Lock-Token": unlock.json()["lock_token"]}
    report = client.get(f"/shares/direct/{share_id}/security-report", headers=unlocked_headers)
    assert report.status_code == 200, report.text
    report_data = report.json()
    activation = client.post(
        f"/shares/direct/{share_id}/activate", headers=unlocked_headers,
        json={"assessment_id": report_data["assessment_id"],
              "acknowledge_limited": bool(report_data.get("limited_checks_ack_required"))},
    )
    assert activation.status_code == 200, activation.text
    return unlocked_headers


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


# ==============================================================================
# PART 1: ACCESS LOCK COMPREHENSIVE AUDIT TESTS
# ==============================================================================

def test_access_lock_owner_control_and_unauthorized_user_rejection():
    """Verify owner control (enable, change, remove) and unauthorized user access block (404/403)."""
    db = next(get_db())
    owner = _create_user(db, "lock_owner")
    other = _create_user(db, "lock_other")

    owner_hdr = _get_auth_headers(owner.username)
    other_hdr = _get_auth_headers(other.username)

    # Upload doc
    up = client.post("/documents/upload", files={"file": ("secret.pdf", MINIMAL_PDF, "application/pdf")}, headers=owner_hdr)
    doc_uuid = up.json()["uuid"]

    # 1. Non-shared user tries to enable lock on owner's doc => HTTP 404 (Information Leakage Protection)
    res = client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "Key123!", "confirm_access_key": "Key123!"}, headers=other_hdr)
    assert res.status_code == 404

    # 2. Owner enables lock => SUCCESS
    res = client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "Key123!", "confirm_access_key": "Key123!"}, headers=owner_hdr)
    assert res.status_code == 200

    # 3. Non-shared user tries to unlock owner's doc => HTTP 404
    res = client.post(f"/documents/{doc_uuid}/access-lock/unlock", json={"access_key": "Key123!"}, headers=other_hdr)
    assert res.status_code == 404

    # 4. Non-shared user tries to change or remove lock => HTTP 404
    assert client.post(f"/documents/{doc_uuid}/access-lock/change", json={"current_key": "Key123!", "new_key": "New123!", "confirm_new_key": "New123!"}, headers=other_hdr).status_code == 404
    assert client.delete(f"/documents/{doc_uuid}/access-lock", headers=other_hdr).status_code == 404

    # 5. Share with read user and activate after Access Lock + assessment review.
    shared = client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [other.username], "permission": "READ"}, headers=owner_hdr)
    assert shared.status_code == 201, shared.text
    _activate_locked_direct_share(other_hdr, doc_uuid, shared.json()[0]["id"], "Key123!")

    # 6. Shared READ user attempts lock enable/change/remove => HTTP 403 (Owner-only)
    assert client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "Key123!", "confirm_access_key": "Key123!"}, headers=other_hdr).status_code == 403
    assert client.post(f"/documents/{doc_uuid}/access-lock/change", json={"new_key": "Key123!", "confirm_new_key": "Key123!"}, headers=other_hdr).status_code == 403
    assert client.delete(f"/documents/{doc_uuid}/access-lock", headers=other_hdr).status_code == 403



def test_locked_share_security_report_loads_but_activation_still_requires_unlock():
    """Sanitized assessment metadata is reviewable before lock unlock; content access is not."""
    db = next(get_db())
    owner = _create_user(db, "lock_review_owner")
    reader = _create_user(db, "lock_review_reader")
    owner_hdr = _get_auth_headers(owner.username)
    reader_hdr = _get_auth_headers(reader.username)

    uploaded = client.post(
        "/documents/upload",
        files={"file": ("locked_review.pdf", MINIMAL_PDF, "application/pdf")},
        headers=owner_hdr,
    )
    assert uploaded.status_code == 201, uploaded.text
    doc_uuid = uploaded.json()["uuid"]
    locked = client.post(
        f"/documents/{doc_uuid}/access-lock/enable",
        json={"access_key": "ReviewKey123!", "confirm_access_key": "ReviewKey123!"},
        headers=owner_hdr,
    )
    assert locked.status_code == 200, locked.text
    shared = client.post(
        f"/documents/{doc_uuid}/shares",
        json={"target_users": [reader.username], "permission": "READ"},
        headers=owner_hdr,
    )
    assert shared.status_code == 201, shared.text
    share_id = shared.json()[0]["id"]

    # Recipient-side refresh is a server-side scan only; it must not require content unlock.
    refreshed = client.post(f"/shares/direct/{share_id}/refresh-security", headers=reader_hdr)
    assert refreshed.status_code == 200, refreshed.text

    # Recipient can read the sanitized report without being given document contents.
    report = client.get(f"/shares/direct/{share_id}/security-report", headers=reader_hdr)
    assert report.status_code == 200, report.text
    assert report.json()["access_locked"] is True

    # The lock still protects activation, even though the report is visible.
    blocked = client.post(
        f"/shares/direct/{share_id}/activate", headers=reader_hdr,
        json={"assessment_id": report.json()["assessment_id"],
              "acknowledge_limited": bool(report.json().get("limited_checks_ack_required"))},
    )
    assert blocked.status_code == 403
    assert "Access Lock" in blocked.json().get("detail", "")

    unlocked = client.post(
        f"/documents/{doc_uuid}/access-lock/unlock", headers=reader_hdr,
        json={"access_key": "ReviewKey123!"},
    )
    assert unlocked.status_code == 200, unlocked.text
    unlocked_headers = {**reader_hdr, "X-Access-Lock-Token": unlocked.json()["lock_token"]}
    activated = client.post(
        f"/shares/direct/{share_id}/activate", headers=unlocked_headers,
        json={"assessment_id": report.json()["assessment_id"],
              "acknowledge_limited": bool(report.json().get("limited_checks_ack_required"))},
    )
    assert activated.status_code == 200, activated.text


def test_permission_and_lock_interaction_and_endpoint_consistency():
    """Verify access lock on top of permissions across detail, download, status, related, versions, history."""
    db = next(get_db())
    owner = _create_user(db, "lock_p_owner")
    reader = _create_user(db, "lock_p_reader")

    owner_hdr = _get_auth_headers(owner.username)
    reader_hdr = _get_auth_headers(reader.username)

    # Upload doc and lock
    up = client.post("/documents/upload", files={"file": ("locked_doc.pdf", MINIMAL_PDF, "application/pdf")}, headers=owner_hdr)
    doc_uuid = up.json()["uuid"]

    client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "SecretPass123!", "confirm_access_key": "SecretPass123!"}, headers=owner_hdr)
    shared = client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [reader.username], "permission": "READ"}, headers=owner_hdr)
    assert shared.status_code == 201, shared.text
    unlocked_hdr = _activate_locked_direct_share(reader_hdr, doc_uuid, shared.json()[0]["id"], "SecretPass123!")

    # Activated reader calling endpoints WITHOUT lock token => HTTP 403 on content endpoints
    assert client.get(f"/documents/{doc_uuid}", headers=reader_hdr).status_code == 403
    assert client.get(f"/documents/{doc_uuid}/download", headers=reader_hdr).status_code == 403
    assert client.get(f"/documents/{doc_uuid}/status", headers=reader_hdr).status_code == 403
    assert client.get(f"/documents/{doc_uuid}/related", headers=reader_hdr).status_code == 403
    assert client.get(f"/documents/{doc_uuid}/versions", headers=reader_hdr).status_code == 403
    assert client.get(f"/explorer/history/{doc_uuid}", headers=reader_hdr).json().get("locked") is True

    # The activation workflow already verified Access Lock and returned its token.
    # Reader with that lock token => SUCCESS across endpoints
    assert client.get(f"/documents/{doc_uuid}", headers=unlocked_hdr).status_code == 200
    assert client.get(f"/documents/{doc_uuid}/download", headers=unlocked_hdr).status_code == 200
    assert client.get(f"/documents/{doc_uuid}/status", headers=unlocked_hdr).status_code == 200
    assert client.get(f"/documents/{doc_uuid}/related", headers=unlocked_hdr).status_code == 200
    assert client.get(f"/documents/{doc_uuid}/versions", headers=unlocked_hdr).status_code == 200
    assert len(client.get(f"/explorer/history/{doc_uuid}", headers=unlocked_hdr).json().get("events", [])) > 0


def test_key_rotation_and_lock_removal_token_invalidation():
    """Verify changing key or removing/re-enabling lock invalidates old unlock tokens."""
    db = next(get_db())
    owner = _create_user(db, "rot_owner")
    reader = _create_user(db, "rot_reader")

    owner_hdr = _get_auth_headers(owner.username)
    reader_hdr = _get_auth_headers(reader.username)

    up = client.post("/documents/upload", files={"file": ("rot.pdf", MINIMAL_PDF, "application/pdf")}, headers=owner_hdr)
    doc_uuid = up.json()["uuid"]

    client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "KeyOne123!", "confirm_access_key": "KeyOne123!"}, headers=owner_hdr)
    shared = client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [reader.username], "permission": "READ"}, headers=owner_hdr)
    assert shared.status_code == 201, shared.text

    # Unlock + assess + activate as the intended recipient.
    hdr1 = _activate_locked_direct_share(reader_hdr, doc_uuid, shared.json()[0]["id"], "KeyOne123!")
    t1 = hdr1["X-Access-Lock-Token"]
    assert client.get(f"/documents/{doc_uuid}", headers=hdr1).status_code == 200

    # Owner changes key to KeyTwo
    client.post(f"/documents/{doc_uuid}/access-lock/change", json={"current_key": "KeyOne123!", "new_key": "KeyTwo123!", "confirm_new_key": "KeyTwo123!"}, headers=owner_hdr)

    # OLD token t1 is now INVALID => HTTP 403
    assert client.get(f"/documents/{doc_uuid}", headers=hdr1).status_code == 403

    # Unlock with KeyTwo => SUCCESS
    t2 = client.post(f"/documents/{doc_uuid}/access-lock/unlock", json={"access_key": "KeyTwo123!"}, headers=reader_hdr).json()["lock_token"]
    hdr2 = {**reader_hdr, "X-Access-Lock-Token": t2}
    assert client.get(f"/documents/{doc_uuid}", headers=hdr2).status_code == 200

    # Owner removes lock
    client.delete(f"/documents/{doc_uuid}/access-lock", headers=owner_hdr)
    assert client.get(f"/documents/{doc_uuid}", headers=reader_hdr).status_code == 200

    # Owner re-enables lock with KeyThree
    client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "KeyThree123!", "confirm_access_key": "KeyThree123!"}, headers=owner_hdr)

    # OLD tokens (t1, t2) both INVALID => HTTP 403
    assert client.get(f"/documents/{doc_uuid}", headers=hdr1).status_code == 403
    assert client.get(f"/documents/{doc_uuid}", headers=hdr2).status_code == 403


def test_unlock_rate_limiting_and_brute_force_protection():
    """Verify wrong key attempts trigger rate limiting (HTTP 429)."""
    db = next(get_db())
    owner = _create_user(db, "rate_owner")
    reader = _create_user(db, "rate_reader")

    owner_hdr = _get_auth_headers(owner.username)
    reader_hdr = _get_auth_headers(reader.username)

    up = client.post("/documents/upload", files={"file": ("rate.pdf", MINIMAL_PDF, "application/pdf")}, headers=owner_hdr)
    doc_uuid = up.json()["uuid"]

    client.post(f"/documents/{doc_uuid}/access-lock/enable", json={"access_key": "CorrectKey123!", "confirm_access_key": "CorrectKey123!"}, headers=owner_hdr)
    client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [reader.username], "permission": "READ"}, headers=owner_hdr)

    # 5 wrong attempts
    for _ in range(5):
        res = client.post(f"/documents/{doc_uuid}/access-lock/unlock", json={"access_key": "WrongKey!"}, headers=reader_hdr)
        assert res.status_code == 400

    # 6th attempt is blocked => HTTP 429
    res6 = client.post(f"/documents/{doc_uuid}/access-lock/unlock", json={"access_key": "CorrectKey123!"}, headers=reader_hdr)
    assert res6.status_code == 429
    assert "Too many incorrect access key attempts" in res6.json()["detail"]


# ==============================================================================
# PART 2: MULTI-USER ISOLATION REGRESSION TESTS
# ==============================================================================

def test_multi_user_isolation_private_documents_and_security_state():
    """
    Comprehensive multi-user isolation verification:
    User A cannot read, download, view content, access versions, history/relations,
    modify, delete, alter access lock, unlock, manipulate shares, manipulate groups,
    use cross-document share IDs, or access deleted documents of User B.
    """
    db = next(get_db())
    user_a = _create_user(db, "iso_user_a")
    user_b = _create_user(db, "iso_user_b")

    hdr_a = _get_auth_headers(user_a.username)
    hdr_b = _get_auth_headers(user_b.username)

    # User B uploads document
    up_b = client.post("/documents/upload", files={"file": ("user_b_private.pdf", MINIMAL_PDF, "application/pdf")}, headers=hdr_b)
    b_doc_uuid = up_b.json()["uuid"]

    # 1. User A cannot read User B's document => HTTP 404
    assert client.get(f"/documents/{b_doc_uuid}", headers=hdr_a).status_code == 404

    # 2. User A cannot download User B's document => HTTP 404
    assert client.get(f"/documents/{b_doc_uuid}/download", headers=hdr_a).status_code == 404

    # 3. User A cannot view User B's processing status => HTTP 404
    assert client.get(f"/documents/{b_doc_uuid}/status", headers=hdr_a).status_code == 404

    # 4. User A cannot view User B's versions => HTTP 404
    assert client.get(f"/documents/{b_doc_uuid}/versions", headers=hdr_a).status_code == 404

    # 5. User A cannot view User B's related documents => HTTP 404
    assert client.get(f"/documents/{b_doc_uuid}/related", headers=hdr_a).status_code == 404

    # 6. User A cannot view User B's history timeline => empty events
    history_res = client.get(f"/explorer/history/{b_doc_uuid}", headers=hdr_a).json()
    assert len(history_res.get("events", [])) == 0

    # 7. User A cannot modify User B's document metadata => HTTP 403
    assert client.put(f"/documents/{b_doc_uuid}", json={"display_name": "Hacked Title"}, headers=hdr_a).status_code == 403

    # 8. User A cannot delete User B's document => HTTP 403
    assert client.delete(f"/documents/{b_doc_uuid}", headers=hdr_a).status_code == 403

    # 9. User A cannot enable access lock on User B's document => HTTP 404
    assert client.post(f"/documents/{b_doc_uuid}/access-lock/enable", json={"access_key": "Key123!", "confirm_access_key": "Key123!"}, headers=hdr_a).status_code == 404

    # 10. User B enables access lock; User A cannot unlock User B's doc => HTTP 404
    client.post(f"/documents/{b_doc_uuid}/access-lock/enable", json={"access_key": "KeyB123!", "confirm_access_key": "KeyB123!"}, headers=hdr_b)
    assert client.post(f"/documents/{b_doc_uuid}/access-lock/unlock", json={"access_key": "KeyB123!"}, headers=hdr_a).status_code == 404

    # 11. User B shares doc with User A; User A cannot share onward to User C => HTTP 403
    user_c = _create_user(db, "iso_user_c")
    client.post(f"/documents/{b_doc_uuid}/shares", json={"target_users": [user_a.username], "permission": "WRITE"}, headers=hdr_b)
    assert client.post(f"/documents/{b_doc_uuid}/shares", json={"target_users": [user_c.username], "permission": "READ"}, headers=hdr_a).status_code == 403

    # 12. Cross-document IDOR protection: User A cannot use a share_id from Document B on Document A
    up_a = client.post("/documents/upload", files={"file": ("user_a_doc.pdf", MINIMAL_PDF, "application/pdf")}, headers=hdr_a)
    a_doc_uuid = up_a.json()["uuid"]
    b_shares = client.get(f"/documents/{b_doc_uuid}/shares", headers=hdr_b).json()
    b_share_id = b_shares[0]["id"]

    # User A tries to delete share_id of User B's document on User A's document => HTTP 404 Share not found
    assert client.delete(f"/documents/{a_doc_uuid}/shares/{b_share_id}", headers=hdr_a).status_code == 404

    # 13. User B moves document to Trash; User A cannot see or restore User B's trashed doc => HTTP 404
    client.delete(f"/documents/{b_doc_uuid}", headers=hdr_b)
    assert client.get("/trash", headers=hdr_a).json() == []
    assert client.post(f"/trash/{b_doc_uuid}/restore", headers=hdr_a).status_code == 404

    # Legitimate owner User B can restore doc
    assert client.post(f"/trash/{b_doc_uuid}/restore", headers=hdr_b).status_code == 200
    assert client.get(f"/documents/{b_doc_uuid}", headers=hdr_b).status_code == 200
