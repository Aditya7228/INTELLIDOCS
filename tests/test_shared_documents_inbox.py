# INTELLIDOCS_SHARING_HUB_REGRESSION_TESTS_V1
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database.connection import SessionLocal, Base, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.group_repo import GroupRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.models.security_assessment import SecurityAssessmentModel
from backend.security.password import PasswordManager
from backend.api.shares import share_key_limiter

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    share_key_limiter.reset_all_for_tests()
    yield
    share_key_limiter.reset_all_for_tests()

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_user(db: Session, prefix: str):
    suffix = uuid.uuid4().hex[:8]
    username = f"{prefix}_{suffix}"
    return UserRepository(db).create_user(
        username=username,
        email=f"{username}@example.com",
        password_hash=PasswordManager.hash_password("Password123!"),
    )

def login(username: str):
    res = client.post("/auth/login", json={"username": username, "password": "Password123!"})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}

def create_doc(db: Session, owner_id: int, name: str = "shared-report.pdf"):
    suffix = uuid.uuid4().hex
    return DocumentRepository(db).create({
        "uuid": suffix,
        "original_name": name,
        "display_name": name,
        "stored_name": f"{suffix}.pdf",
        "file_path": f"uploads/{suffix}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 128,
        "sha256_hash": uuid.uuid4().hex * 2,
        "owner_id": owner_id,
        "processing_status": "done",
    })

def add_safe_assessment(db: Session, doc, owner_id: int, scanner_status="AVAILABLE"):
    rec = SecurityAssessmentModel(
        quarantine_uuid=str(uuid.uuid4()), document_id=doc.id, owner_id=owner_id,
        original_name=doc.original_name, stored_quarantine_name=f"{uuid.uuid4()}.pdf",
        file_type="pdf", mime_type="application/pdf", size_bytes=128,
        sha256_hash=doc.sha256_hash, risk_score=0, risk_level="LOW RISK",
        confidence="HIGH" if scanner_status == "AVAILABLE" else "MEDIUM",
        verdict="SAFE", data_sensitivity="public", pii_detected=0,
        scanner_status=scanner_status, check_states_json="{}", findings_json="[]",
        why_explanations_json="[]", potential_harms_json="[]",
        recommended_action="Available checks completed", quarantine_status="PROMOTED",
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec

def activate_received_share(headers, source: str, share_id: int):
    report = client.get(f"/shares/{source}/{share_id}/security-report", headers=headers)
    assert report.status_code == 200, report.text
    payload = report.json()
    result = client.post(
        f"/shares/{source}/{share_id}/activate", headers=headers,
        json={"assessment_id": payload["assessment_id"],
              "acknowledge_limited": bool(payload.get("limited_checks_ack_required"))},
    )
    assert result.status_code == 200, result.text
    return result.json()


def test_received_inbox_handles_direct_and_group_shares(db_session: Session):
    owner = create_user(db_session, "inbox_owner")
    receiver = create_user(db_session, "inbox_receiver")
    owner_headers, receiver_headers = login(owner.username), login(receiver.username)
    doc = create_doc(db_session, owner.id)
    add_safe_assessment(db_session, doc, owner.id)

    direct = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [receiver.username], "permission": "READ"},
    )
    assert direct.status_code == 201, direct.text

    group = client.post(
        "/groups", headers=owner_headers,
        json={"name": f"InboxGroup_{uuid.uuid4().hex[:6]}", "member_usernames": [receiver.username]},
    )
    assert group.status_code == 201, group.text
    group_id = group.json()["id"]
    group_share = client.post(
        f"/groups/{group_id}/shares", headers=owner_headers,
        json={"document_uuid": doc.uuid, "permission": "READ"},
    )
    assert group_share.status_code == 201, group_share.text

    received = client.get("/shares/received", headers=receiver_headers)
    assert received.status_code == 200, received.text
    rows = [x for x in received.json() if x["document_uuid"] == doc.uuid]
    assert {x["source"] for x in rows} == {"direct", "group"}
    assert all(x["access_activated"] is False for x in rows)
    group_row = next(x for x in rows if x["source"] == "group")
    direct_row = next(x for x in rows if x["source"] == "direct")
    assert group_row["group_id"] == group_id
    assert group_row["security_status"] == "PASSED"
    assert group_row["access_locked"] is False

    # Pending shares are visible only in Received by Me; not in Documents or Graph.
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 404
    docs = client.get("/documents", headers=receiver_headers)
    assert docs.status_code == 200
    assert all(item["uuid"] != doc.uuid for item in docs.json())
    graph = client.get("/explorer/graph", headers=receiver_headers)
    assert graph.status_code == 200
    assert all(node.get("details", {}).get("uuid") != doc.uuid for node in graph.json()["nodes"])

    activate_received_share(receiver_headers, "direct", direct_row["id"])
    activate_received_share(receiver_headers, "group", group_row["id"])
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 200
    docs_after = client.get("/documents", headers=receiver_headers).json()
    assert any(item["uuid"] == doc.uuid for item in docs_after)
    graph_after = client.get("/explorer/graph", headers=receiver_headers).json()
    assert any(node.get("details", {}).get("uuid") == doc.uuid for node in graph_after["nodes"])


def test_shared_inbox_never_labels_missing_assessment_as_passed(db_session: Session):
    owner = create_user(db_session, "inbox_noassessment_owner")
    receiver = create_user(db_session, "inbox_noassessment_receiver")
    owner_headers, receiver_headers = login(owner.username), login(receiver.username)
    doc = create_doc(db_session, owner.id, "legacy-unassessed.pdf")
    rejected = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [receiver.username], "permission": "READ"},
    )
    assert rejected.status_code == 409, rejected.text
    assert "security assessment" in rejected.json()["detail"].lower()

    # Simulate a legacy share created before this gate existed: it can appear in the inbox,
    # but the recipient cannot read its contents until it has a cleared assessment.
    ShareRepository(db_session).create_direct_share(
        document_id=doc.id, owner_id=owner.id, target_user_id=receiver.id, permission="READ"
    )
    received = client.get("/shares/received", headers=receiver_headers)
    assert received.status_code == 200, received.text
    row = next(x for x in received.json() if x["document_uuid"] == doc.uuid)
    assert row["security_status"] == "NOT_ASSESSED"
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 404

def test_sent_shares_are_scoped_to_document_owner(db_session: Session):
    owner = create_user(db_session, "sent_owner")
    recipient = create_user(db_session, "sent_recipient")
    outsider = create_user(db_session, "sent_outsider")
    owner_headers, outsider_headers = login(owner.username), login(outsider.username)
    doc = create_doc(db_session, owner.id, "outgoing.pdf")
    add_safe_assessment(db_session, doc, owner.id)
    create = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [recipient.username], "permission": "READ"},
    )
    assert create.status_code == 201, create.text
    sent = client.get("/shares/sent", headers=owner_headers)
    assert sent.status_code == 200, sent.text
    assert any(x["document_uuid"] == doc.uuid and x["target_username"] == recipient.username for x in sent.json())
    outsider_sent = client.get("/shares/sent", headers=outsider_headers)
    assert outsider_sent.status_code == 200, outsider_sent.text
    assert all(x["owner_id"] == outsider.id for x in outsider_sent.json())


def test_limited_scanner_requires_ack_and_stale_report_cannot_activate(db_session: Session):
    owner = create_user(db_session, "limited_owner")
    receiver = create_user(db_session, "limited_receiver")
    owner_headers, receiver_headers = login(owner.username), login(receiver.username)
    doc = create_doc(db_session, owner.id, "limited-scanner.pdf")
    add_safe_assessment(db_session, doc, owner.id, scanner_status="UNAVAILABLE")

    share = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [receiver.username], "permission": "READ"},
    )
    assert share.status_code == 201, share.text
    share_id = share.json()[0]["id"]
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 404

    report = client.get(f"/shares/direct/{share_id}/security-report", headers=receiver_headers)
    assert report.status_code == 200, report.text
    payload = report.json()
    assert payload["security_status"] == "LIMITED"
    assert payload["limited_checks_ack_required"] is True
    assert payload["can_activate"] is True

    missing_ack = client.post(
        f"/shares/direct/{share_id}/activate", headers=receiver_headers,
        json={"assessment_id": payload["assessment_id"], "acknowledge_limited": False},
    )
    assert missing_ack.status_code == 409

    # A later assessment supersedes the report; stale report IDs cannot grant access.
    add_safe_assessment(db_session, doc, owner.id, scanner_status="UNAVAILABLE")
    stale_report = client.post(
        f"/shares/direct/{share_id}/activate", headers=receiver_headers,
        json={"assessment_id": payload["assessment_id"], "acknowledge_limited": True},
    )
    assert stale_report.status_code == 409
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 404

    fresh_report = client.get(f"/shares/direct/{share_id}/security-report", headers=receiver_headers)
    assert fresh_report.status_code == 200
    accepted = client.post(
        f"/shares/direct/{share_id}/activate", headers=receiver_headers,
        json={"assessment_id": fresh_report.json()["assessment_id"], "acknowledge_limited": True},
    )
    assert accepted.status_code == 200, accepted.text
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 200


def test_share_key_verification_is_rate_limited(db_session: Session):
    owner = create_user(db_session, "keylimit_owner")
    receiver = create_user(db_session, "keylimit_receiver")
    owner_headers, receiver_headers = login(owner.username), login(receiver.username)
    doc = create_doc(db_session, owner.id, "protected-share.pdf")
    add_safe_assessment(db_session, doc, owner.id)
    created = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [receiver.username], "permission": "READ", "protect_with_key": True},
    )
    assert created.status_code == 201, created.text
    share_id = created.json()[0]["id"]
    wrong = {"key": "definitely-not-the-real-key"}
    for _ in range(5):
        res = client.post(f"/documents/{doc.uuid}/shares/{share_id}/verify-key", headers=receiver_headers, json=wrong)
        assert res.status_code == 403, res.text
    blocked = client.post(f"/documents/{doc.uuid}/shares/{share_id}/verify-key", headers=receiver_headers, json=wrong)
    assert blocked.status_code == 429, blocked.text


def test_security_gate_blocks_unsafe_assessment_and_legacy_access(db_session: Session):
    owner = create_user(db_session, "gate_unsafe_owner")
    receiver = create_user(db_session, "gate_unsafe_receiver")
    owner_headers, receiver_headers = login(owner.username), login(receiver.username)
    doc = create_doc(db_session, owner.id, "unsafe-shared.pdf")
    assessment = add_safe_assessment(db_session, doc, owner.id)
    assessment.verdict = "SUSPICIOUS"
    assessment.quarantine_status = "QUARANTINED"
    db_session.commit()

    direct = client.post(
        f"/documents/{doc.uuid}/shares", headers=owner_headers,
        json={"target_users": [receiver.username], "permission": "READ"},
    )
    assert direct.status_code == 409, direct.text

    group_res = client.post(
        "/groups", headers=owner_headers,
        json={"name": f"UnsafeGroup_{uuid.uuid4().hex[:6]}", "member_usernames": [receiver.username]},
    )
    assert group_res.status_code == 201, group_res.text
    group_id = group_res.json()["id"]
    group_share_res = client.post(
        f"/groups/{group_id}/shares", headers=owner_headers,
        json={"document_uuid": doc.uuid, "permission": "READ"},
    )
    assert group_share_res.status_code == 409, group_share_res.text

    # Simulate pre-existing grants: permission checks still deny access after a bad assessment.
    ShareRepository(db_session).create_direct_share(
        document_id=doc.id, owner_id=owner.id, target_user_id=receiver.id, permission="READ"
    )
    ShareRepository(db_session).create_group_share(
        document_id=doc.id, group_id=group_id, owner_id=owner.id, permission="READ"
    )
    received = client.get("/shares/received", headers=receiver_headers)
    assert received.status_code == 200, received.text
    rows = [x for x in received.json() if x["document_uuid"] == doc.uuid]
    assert rows and all(x["security_status"] == "QUARANTINED" for x in rows)
    assert client.get(f"/documents/{doc.uuid}", headers=receiver_headers).status_code == 404
