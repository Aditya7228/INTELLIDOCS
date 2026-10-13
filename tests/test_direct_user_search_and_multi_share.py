import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.main import app
from backend.database.connection import SessionLocal, Base, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.share_repo import ShareRepository
from backend.models.security_assessment import SecurityAssessmentModel
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
    suffix = uuid.uuid4().hex[:6]
    username = f"{prefix}_{suffix}"
    email = f"{username}@example.com"
    pwd_hash = PasswordManager.hash_password("Password123!")
    user = repo.create_user(username=username, email=email, password_hash=pwd_hash)
    return user



def _add_safe_assessment(db: Session, doc, owner_id: int):
    """Give manually-created test documents the same cleared assessment as uploaded files."""
    assessment = SecurityAssessmentModel(
        quarantine_uuid=str(uuid.uuid4()), document_id=doc.id, owner_id=owner_id,
        original_name=doc.original_name, stored_quarantine_name=f"{uuid.uuid4()}.pdf",
        file_type="pdf", mime_type="application/pdf", size_bytes=doc.size_bytes,
        sha256_hash=doc.sha256_hash, risk_score=0, risk_level="LOW RISK",
        confidence="HIGH", verdict="SAFE", data_sensitivity="public", pii_detected=0,
        scanner_status="AVAILABLE", check_states_json="{}", findings_json="[]",
        why_explanations_json="[]", potential_harms_json="[]",
        recommended_action="Available checks completed", quarantine_status="PROMOTED",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


def _get_auth_headers(username: str, password: str = "Password123!"):
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _activate_received_share(headers, source: str, share_id: int):
    report = client.get(f"/shares/{source}/{share_id}/security-report", headers=headers)
    assert report.status_code == 200, report.text
    report_data = report.json()
    activated = client.post(
        f"/shares/{source}/{share_id}/activate", headers=headers,
        json={"assessment_id": report_data["assessment_id"],
              "acknowledge_limited": bool(report_data.get("limited_checks_ack_required"))},
    )
    assert activated.status_code == 200, activated.text
    return activated.json()


def test_user_search_authorization_and_privacy(db_session: Session):
    owner = _create_test_user(db_session, "search_owner")
    target1 = _create_test_user(db_session, "abhishek_user")
    target2 = _create_test_user(db_session, "shreyash_user")

    # 1. Unauthenticated search rejected
    res_unauth = client.get("/users/search?q=abhishek")
    assert res_unauth.status_code == 401

    # 2. Authenticated search
    headers = _get_auth_headers(owner.username)
    res = client.get("/users/search?q=abhishek", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    hit = data[0]
    assert "id" in hit
    assert "username" in hit
    assert "email" in hit
    # Privacy check: sensitive fields MUST NOT be exposed
    assert "password_hash" not in hit
    assert "secret_encrypted" not in hit
    assert "totp_secret" not in hit

    # 3. Search excludes self
    res_self = client.get(f"/users/search?q={owner.username}", headers=headers)
    assert res_self.status_code == 200
    data_self = res_self.json()
    assert all(u["id"] != owner.id for u in data_self)


def test_search_nonexistent_user_returns_empty(db_session: Session):
    owner = _create_test_user(db_session, "nonexist_owner")
    headers = _get_auth_headers(owner.username)

    res = client.get("/users/search?q=nonexistent_user_99999", headers=headers)
    assert res.status_code == 200
    assert res.json() == []


def test_multi_user_share_success_read_append_write(db_session: Session):
    owner = _create_test_user(db_session, "multi_owner")
    u1 = _create_test_user(db_session, "recipient_alpha")
    u2 = _create_test_user(db_session, "recipient_beta")
    u3 = _create_test_user(db_session, "recipient_gamma")

    doc_repo = DocumentRepository(db_session)
    doc_uuid = f"multi-share-doc-{uuid.uuid4().hex[:8]}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": "Project_Plan.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 15000,
        "sha256_hash": "f"*64,
        "owner_id": owner.id,
        "processing_status": "done"
    })
    _add_safe_assessment(db_session, doc, owner.id)

    headers = _get_auth_headers(owner.username)

    # Share with 3 recipients (READ permission)
    res = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers,
        json={
            "target_users": [u1.username, u2.username, u3.email],
            "permission": "READ"
        }
    )
    assert res.status_code == 201
    shares_data = res.json()
    assert len(shares_data) == 3
    target_usernames = {s["target_username"] for s in shares_data}
    assert u1.username in target_usernames
    assert u2.username in target_usernames
    assert u3.username in target_usernames

    # A share remains pending until the recipient reviews and activates it.
    headers_u1 = _get_auth_headers(u1.username)
    assert client.get(f"/documents/{doc_uuid}", headers=headers_u1).status_code == 404
    received_u1 = client.get("/shares/received", headers=headers_u1)
    row_u1 = next(x for x in received_u1.json() if x["document_uuid"] == doc_uuid and x["source"] == "direct")
    assert row_u1["access_activated"] is False
    docs_u1 = client.get("/documents", headers=headers_u1).json()
    assert all(item["uuid"] != doc_uuid for item in docs_u1)
    graph_u1 = client.get("/explorer/graph", headers=headers_u1).json()
    assert all(node.get("details", {}).get("uuid") != doc_uuid for node in graph_u1["nodes"])

    # Activate each grant independently (the second two are not used in this assertion,
    # but they demonstrate that a multi-recipient share has per-recipient acceptance).
    for entry, user in zip(shares_data, [u1, u2, u3]):
        recipient_headers = _get_auth_headers(user.username)
        _activate_received_share(recipient_headers, "direct", entry["id"])

    res_u1 = client.get(f"/documents/{doc_uuid}", headers=headers_u1)
    assert res_u1.status_code == 200
    assert res_u1.json()["user_permission"] == "READ"


def test_share_max_5_recipients_limit(db_session: Session):
    owner = _create_test_user(db_session, "limit_owner")
    recipients = [_create_test_user(db_session, f"limit_rec_{i}") for i in range(6)]

    doc_repo = DocumentRepository(db_session)
    doc_uuid = f"limit-share-doc-{uuid.uuid4().hex[:8]}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": "Limit_Doc.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 10000,
        "sha256_hash": "g"*64,
        "owner_id": owner.id,
        "processing_status": "done"
    })
    _add_safe_assessment(db_session, doc, owner.id)

    headers = _get_auth_headers(owner.username)

    # 6 recipients must be rejected by validator
    res_over = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers,
        json={
            "target_users": [r.username for r in recipients],
            "permission": "WRITE"
        }
    )
    assert res_over.status_code in (400, 422)


def test_cannot_share_with_self(db_session: Session):
    owner = _create_test_user(db_session, "self_owner")

    doc_repo = DocumentRepository(db_session)
    doc_uuid = f"self-share-doc-{uuid.uuid4().hex[:8]}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": "Self_Doc.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 10000,
        "sha256_hash": "h"*64,
        "owner_id": owner.id,
        "processing_status": "done"
    })
    _add_safe_assessment(db_session, doc, owner.id)

    headers = _get_auth_headers(owner.username)

    res_self = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers,
        json={
            "target_users": [owner.username],
            "permission": "READ"
        }
    )
    assert res_self.status_code == 400
    assert "yourself" in res_self.json()["detail"].lower()


def test_already_shared_user_handling_no_duplicates(db_session: Session):
    owner = _create_test_user(db_session, "dup_share_owner")
    target = _create_test_user(db_session, "dup_share_target")

    doc_repo = DocumentRepository(db_session)
    doc_uuid = f"dup-share-doc-{uuid.uuid4().hex[:8]}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": "Dup_Share_Doc.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 12000,
        "sha256_hash": "i"*64,
        "owner_id": owner.id,
        "processing_status": "done"
    })
    _add_safe_assessment(db_session, doc, owner.id)

    headers = _get_auth_headers(owner.username)

    # 1st Share: READ
    res1 = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers,
        json={"target_users": [target.username], "permission": "READ"}
    )
    assert res1.status_code == 201

    # 2nd Share: APPEND (Updates permission cleanly without creating duplicate DB row)
    res2 = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers,
        json={"target_users": [target.username], "permission": "APPEND"}
    )
    assert res2.status_code == 201
    assert res2.json()[0]["permission"] == "APPEND"

    # Verify active shares count is 1
    share_repo = ShareRepository(db_session)
    active_shares = share_repo.list_active_direct_shares_for_document(doc.id)
    assert len(active_shares) == 1


def test_unauthorized_user_cannot_share_or_manipulate(db_session: Session):
    owner = _create_test_user(db_session, "unauth_owner")
    attacker = _create_test_user(db_session, "unauth_attacker")
    victim = _create_test_user(db_session, "unauth_victim")

    doc_repo = DocumentRepository(db_session)
    doc_uuid = f"unauth-share-doc-{uuid.uuid4().hex[:8]}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": "Private_Owner_Doc.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 18000,
        "sha256_hash": "j"*64,
        "owner_id": owner.id,
        "processing_status": "done"
    })
    _add_safe_assessment(db_session, doc, owner.id)

    headers_attacker = _get_auth_headers(attacker.username)

    # Attacker attempts to share owner's document (IDOR attempt)
    res_share = client.post(
        f"/documents/{doc_uuid}/shares",
        headers=headers_attacker,
        json={"target_users": [victim.username], "permission": "WRITE"}
    )
    assert res_share.status_code == 403

    # Attacker attempts to list shares of owner's document
    res_list = client.get(f"/documents/{doc_uuid}/shares", headers=headers_attacker)
    assert res_list.status_code == 403
