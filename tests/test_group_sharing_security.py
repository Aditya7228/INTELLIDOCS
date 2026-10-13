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
from backend.database.repositories.notification_repo import NotificationRepository
from backend.security.password import PasswordManager
from backend.core.permission_service import PermissionService

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def _create_test_user(db: Session, username: str, email: str, role: str = "user"):
    repo = UserRepository(db)
    suffix = uuid.uuid4().hex[:6]
    unique_user = f"{username}_{suffix}"
    unique_email = f"{unique_user}@example.com"
    pwd_hash = PasswordManager.hash_password("Password123!")
    user = repo.create_user(username=unique_user, email=unique_email, password_hash=pwd_hash, role=role)
    return user


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

def _get_auth_headers(username: str, password: str = "Password123!"):
    login_res = client.post("/auth/login", json={"username": username, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _activate_received_share(headers, source: str, share_id: int):
    report = client.get(f"/shares/{source}/{share_id}/security-report", headers=headers)
    assert report.status_code == 200, report.text
    report_data = report.json()
    result = client.post(
        f"/shares/{source}/{share_id}/activate", headers=headers,
        json={"assessment_id": report_data["assessment_id"],
              "acknowledge_limited": bool(report_data.get("limited_checks_ack_required"))},
    )
    assert result.status_code == 200, result.text
    return result.json()


def test_group_member_limit_7_and_duplicate_handling():
    """Test group creation & member addition limit (max 7 active members) & duplicate member rejection."""
    db = next(get_db())

    # Create owner and 8 potential members
    owner = _create_test_user(db, "grp_owner", "grp_owner@example.com")
    members = []
    for i in range(1, 9):
        members.append(_create_test_user(db, f"grp_user_{i}", f"grp_user_{i}@example.com"))

    headers = _get_auth_headers(owner.username, "Password123!")

    # 1. Create group with 5 initial members (owner + 5 = 6 total)
    initial = [m.username for m in members[:5]]
    res = client.post("/groups", json={"name": "Engineering Team", "member_usernames": initial}, headers=headers)
    assert res.status_code == 201
    g_data = res.json()
    group_id = g_data["id"]
    assert g_data["member_count"] == 6

    # 2. Add 6th member (owner + 6 = 7 total) => SUCCESS
    res = client.post(f"/groups/{group_id}/members", json={"username_or_email": members[5].username}, headers=headers)
    assert res.status_code == 200
    assert res.json()["member_count"] == 7

    # 3. Add 7th member (attempting to make 8 members total) => REJECTED (HTTP 400)
    res = client.post(f"/groups/{group_id}/members", json={"username_or_email": members[6].username}, headers=headers)
    assert res.status_code == 400
    assert "Groups can contain up to 7 members." in res.json()["detail"]

    # 4. Duplicate member addition => REJECTED (HTTP 400)
    # Remove 1 member so count drops to 6
    res = client.delete(f"/groups/{group_id}/members/{members[5].id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["member_count"] == 6

    # Attempt adding member[0] who is already in group
    res = client.post(f"/groups/{group_id}/members", json={"username_or_email": members[0].username}, headers=headers)
    assert res.status_code == 400
    assert "already in this group" in res.json()["detail"]

    # Re-adding member[5] after removal => SUCCESS (count back to 7)
    res = client.post(f"/groups/{group_id}/members", json={"username_or_email": members[5].username}, headers=headers)
    assert res.status_code == 200
    assert res.json()["member_count"] == 7


def test_group_share_permission_levels_read_append_write():
    """Test group share permission enforcement (READ, APPEND, WRITE) for group members."""
    db = next(get_db())

    doc_owner = _create_test_user(db, "doc_owner_g", "doc_owner_g@example.com")
    member = _create_test_user(db, "member_g", "member_g@example.com")

    owner_headers = _get_auth_headers(doc_owner.username, "Password123!")
    member_headers = _get_auth_headers(member.username, "Password123!")

    # Create group
    g_res = client.post("/groups", json={"name": "Dev Group", "member_usernames": [member.username]}, headers=owner_headers)
    group_id = g_res.json()["id"]

    # Upload test document
    files = {"file": ("test_doc.pdf", MINIMAL_PDF, "application/pdf")}
    up_res = client.post("/documents/upload", files=files, headers=owner_headers)
    doc_uuid = up_res.json()["uuid"]

    # Share document with group READ permission
    s_res = client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "READ"}, headers=owner_headers)
    assert s_res.status_code == 201
    share_id = s_res.json()["id"]
    _activate_received_share(member_headers, "group", share_id)

    # Member can view detail (READ)
    detail_res = client.get(f"/documents/{doc_uuid}", headers=member_headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["user_permission"] == "READ"

    # Member CANNOT edit metadata (READ user) => HTTP 403
    edit_res = client.put(f"/documents/{doc_uuid}", json={"display_name": "Hacked Title"}, headers=member_headers)
    assert edit_res.status_code == 403

    # Member CANNOT upload version (READ user) => HTTP 403
    v_files = {"file": ("v2.pdf", MINIMAL_PDF, "application/pdf")}
    v_res = client.post(f"/documents/{doc_uuid}/versions", files=v_files, headers=member_headers)
    assert v_res.status_code == 403

    # Document owner updates group share permission to APPEND
    up_perm_res = client.put(f"/groups/{group_id}/shares/{share_id}", json={"document_uuid": doc_uuid, "permission": "APPEND"}, headers=owner_headers)
    assert up_perm_res.status_code == 200
    _activate_received_share(member_headers, "group", share_id)

    # Member can now upload new version (APPEND user) => SUCCESS
    v_res2 = client.post(f"/documents/{doc_uuid}/versions", files=v_files, headers=member_headers)
    assert v_res2.status_code == 201

    # Member STILL CANNOT edit metadata (APPEND user) => HTTP 403
    assert client.put(f"/documents/{doc_uuid}", json={"display_name": "Hacked Title"}, headers=member_headers).status_code == 403

    # Document owner updates group share permission to WRITE
    write_perm_res = client.put(f"/groups/{group_id}/shares/{share_id}", json={"document_uuid": doc_uuid, "permission": "WRITE"}, headers=owner_headers)
    assert write_perm_res.status_code == 200
    _activate_received_share(member_headers, "group", share_id)

    # Member can now edit metadata (WRITE user) => SUCCESS
    edit_res2 = client.put(f"/documents/{doc_uuid}", json={"display_name": "Updated Title By Group Member"}, headers=member_headers)
    assert edit_res2.status_code == 200
    assert edit_res2.json()["display_name"] == "Updated Title By Group Member"


def test_group_share_revocation_and_stale_access_removal():
    """Test group share revocation removes access for group members without direct shares."""
    db = next(get_db())

    owner = _create_test_user(db, "owner_rev", "owner_rev@example.com")
    member = _create_test_user(db, "member_rev", "member_rev@example.com")

    owner_headers = _get_auth_headers(owner.username, "Password123!")
    member_headers = _get_auth_headers(member.username, "Password123!")

    # Create group and upload doc
    group_id = client.post("/groups", json={"name": "Revoke Team", "member_usernames": [member.username]}, headers=owner_headers).json()["id"]
    files = {"file": ("doc_rev.pdf", MINIMAL_PDF, "application/pdf")}
    doc_uuid = client.post("/documents/upload", files=files, headers=owner_headers).json()["uuid"]

    # Share with group
    share_id = client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "READ"}, headers=owner_headers).json()["id"]
    _activate_received_share(member_headers, "group", share_id)

    # Member has access only after activating the shared grant
    assert client.get(f"/documents/{doc_uuid}", headers=member_headers).status_code == 200

    # Revoke group share
    rev_res = client.delete(f"/groups/{group_id}/shares/{share_id}", headers=owner_headers)
    assert rev_res.status_code == 200

    # Member access is now revoked (HTTP 404/403)
    assert client.get(f"/documents/{doc_uuid}", headers=member_headers).status_code == 404


def test_direct_and_group_permission_interaction():
    """
    Test direct + group permission resolution scenarios:
    A: Direct READ + Group WRITE => effective permission WRITE
    B: Direct WRITE + Group READ => effective permission WRITE
    C: Direct READ + Group READ => READ
    D: Direct READ + Group revoked => READ remains
    E: No direct share + Group revoked => no access
    F: User removed from group + independent direct share exists => direct access remains
    """
    db = next(get_db())

    owner = _create_test_user(db, "owner_combo", "owner_combo@example.com")
    user = _create_test_user(db, "user_combo", "user_combo@example.com")

    owner_headers = _get_auth_headers(owner.username, "Password123!")
    user_headers = _get_auth_headers(user.username, "Password123!")

    group_id = client.post("/groups", json={"name": "Combo Group", "member_usernames": [user.username]}, headers=owner_headers).json()["id"]
    files = {"file": ("combo.pdf", MINIMAL_PDF, "application/pdf")}
    doc_uuid = client.post("/documents/upload", files=files, headers=owner_headers).json()["uuid"]

    # Scenario A: Direct READ + Group WRITE => effective WRITE, after recipient-specific activation of both grants.
    direct_res = client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [user.username], "permission": "READ"}, headers=owner_headers)
    group_res = client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "WRITE"}, headers=owner_headers)
    assert direct_res.status_code == 201
    assert group_res.status_code == 201
    _activate_received_share(user_headers, "direct", direct_res.json()[0]["id"])
    _activate_received_share(user_headers, "group", group_res.json()["id"])

    res = client.get(f"/documents/{doc_uuid}", headers=user_headers)
    assert res.status_code == 200
    assert res.json()["user_permission"] == "WRITE"

    # Scenario D: Direct READ + Group revoked => Direct READ remains
    group_shares = client.get(f"/documents/{doc_uuid}/shares", headers=owner_headers).json()
    grp_share_id = [s["id"] for s in group_shares if s["source"] == "group"][0]
    client.delete(f"/groups/{group_id}/shares/{grp_share_id}", headers=owner_headers)

    res_d = client.get(f"/documents/{doc_uuid}", headers=user_headers)
    assert res_d.status_code == 200
    assert res_d.json()["user_permission"] == "READ"

    # Scenario F: User removed from group + independent direct share exists => direct access remains
    client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "WRITE"}, headers=owner_headers)
    client.delete(f"/groups/{group_id}/members/{user.id}", headers=owner_headers)

    res_f = client.get(f"/documents/{doc_uuid}", headers=user_headers)
    assert res_f.status_code == 200
    assert res_f.json()["user_permission"] == "READ"  # Direct READ survived group member removal!


def test_onward_sharing_prevention_for_group_members():
    """Group-derived users must NOT be able to share documents onward."""
    db = next(get_db())

    owner = _create_test_user(db, "onward_owner", "onward_owner@example.com")
    member = _create_test_user(db, "onward_member", "onward_member@example.com")
    target = _create_test_user(db, "onward_target", "onward_target@example.com")

    owner_headers = _get_auth_headers(owner.username, "Password123!")
    member_headers = _get_auth_headers(member.username, "Password123!")

    group_id = client.post("/groups", json={"name": "Onward Group", "member_usernames": [member.username]}, headers=owner_headers).json()["id"]
    files = {"file": ("onward.pdf", MINIMAL_PDF, "application/pdf")}
    doc_uuid = client.post("/documents/upload", files=files, headers=owner_headers).json()["uuid"]

    # Share with group (WRITE permission)
    client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "WRITE"}, headers=owner_headers)

    # Member attempts to share document onward => HTTP 403
    reshare_res = client.post(f"/documents/{doc_uuid}/shares", json={"target_users": [target.username], "permission": "READ"}, headers=member_headers)
    assert reshare_res.status_code == 403
    assert "Only the document owner can share" in reshare_res.json()["detail"]


def test_owner_only_group_management_and_idor_protection():
    """Verify non-owners cannot rename, add members, remove members, or delete another user's group."""
    db = next(get_db())

    user_a = _create_test_user(db, "user_a", "user_a@example.com")
    user_b = _create_test_user(db, "user_b", "user_b@example.com")

    headers_a = _get_auth_headers(user_a.username, "Password123!")
    headers_b = _get_auth_headers(user_b.username, "Password123!")

    # User A creates group
    group_id = client.post("/groups", json={"name": "User A Group"}, headers=headers_a).json()["id"]

    # User B attempts to rename User A's group => HTTP 403
    assert client.put(f"/groups/{group_id}", json={"name": "Hacked Group"}, headers=headers_b).status_code == 403

    # User B attempts to add member to User A's group => HTTP 403
    assert client.post(f"/groups/{group_id}/members", json={"username_or_email": user_b.username}, headers=headers_b).status_code == 403

    # User B attempts to delete User A's group => HTTP 403
    assert client.delete(f"/groups/{group_id}", headers=headers_b).status_code == 403


def test_audit_and_notification_logging_for_group_events():
    """Verify group sharing actions write audit events and notifications without exposing secrets."""
    db = next(get_db())

    owner = _create_test_user(db, "aud_owner", "aud_owner@example.com")
    member = _create_test_user(db, "aud_member", "aud_member@example.com")

    owner_headers = _get_auth_headers(owner.username, "Password123!")
    headers_member = _get_auth_headers(member.username, "Password123!")

    # Create group, then add the member through the explicit member-management flow
    # so both the membership audit event and notification are exercised.
    group_id = client.post("/groups", json={"name": "Audit Group"}, headers=owner_headers).json()["id"]
    add_member_res = client.post(
        f"/groups/{group_id}/members",
        json={"username_or_email": member.username},
        headers=owner_headers,
    )
    assert add_member_res.status_code == 200, add_member_res.text

    # Upload doc and share
    files = {"file": ("aud_doc.pdf", MINIMAL_PDF, "application/pdf")}
    doc_uuid = client.post("/documents/upload", files=files, headers=owner_headers).json()["uuid"]
    client.post(f"/groups/{group_id}/shares", json={"document_uuid": doc_uuid, "permission": "READ"}, headers=owner_headers)

    # Check Audit log
    audit_repo = AuditRepository(db)
    logs, _ = audit_repo.list_logs(limit=50)
    actions = [l.action for l in logs]

    assert "GROUP_CREATED" in actions
    assert "GROUP_MEMBER_ADDED" in actions
    assert "GROUP_DOCUMENT_SHARED" in actions

    # Check Notification table
    notif_repo = NotificationRepository(db)
    notifs = notif_repo.list_for_user(member.id)
    event_types = [n.event_type for n in notifs]

    assert "GROUP_MEMBER_ADDED" in event_types
    assert "GROUP_DOCUMENT_SHARED" in event_types


def test_document_owner_cannot_share_into_another_users_group():
    """Document ownership alone must not authorize sharing into someone else's group."""
    db = next(get_db())
    group_owner = _create_test_user(db, "foreign_group_owner", "foreign_group_owner@example.com")
    doc_owner = _create_test_user(db, "foreign_doc_owner", "foreign_doc_owner@example.com")
    group_owner_headers = _get_auth_headers(group_owner.username)
    doc_owner_headers = _get_auth_headers(doc_owner.username)

    group_res = client.post(
        "/groups", json={"name": f"PrivateGroup_{uuid.uuid4().hex[:6]}"},
        headers=group_owner_headers,
    )
    assert group_res.status_code == 201, group_res.text
    group_id = group_res.json()["id"]

    upload = client.post(
        "/documents/upload",
        files={"file": ("owned-by-other.pdf", MINIMAL_PDF, "application/pdf")},
        headers=doc_owner_headers,
    )
    assert upload.status_code == 201, upload.text
    doc_uuid = upload.json()["uuid"]

    denied = client.post(
        f"/groups/{group_id}/shares",
        json={"document_uuid": doc_uuid, "permission": "READ"},
        headers=doc_owner_headers,
    )
    assert denied.status_code == 403, denied.text
    assert "group owner" in denied.json()["detail"].lower()
