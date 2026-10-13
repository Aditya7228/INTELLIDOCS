"""Focused regressions for active shared-document recipient behavior."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.database.connection import Base, SessionLocal, engine
from backend.database.migrations import run_migrations
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document import DocumentModel
from backend.models.document_share import DocumentShare
from backend.models.security_assessment import SecurityAssessmentModel
from backend.models.suggestion import DocumentSuggestion
from backend.models.user_document_preference import UserDocumentPreference
from backend.models.folder import FolderModel
from backend.security.password import PasswordManager
from backend.security.jwt_handler import JWTHandler

client = TestClient(app)


@pytest.fixture(autouse=True)
def ensure_schema():
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    yield


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def make_user(db: Session, stem: str):
    suffix = uuid.uuid4().hex[:8]
    username = f"{stem}_{suffix}"
    return UserRepository(db).create_user(
        username=username,
        email=f"{username}@example.com",
        password_hash=PasswordManager.hash_password("Password123!"),
    )


def make_doc(db: Session, owner_id: int, name: str, sha: str = None, text: str = ""):
    doc_uuid = str(uuid.uuid4())
    return DocumentRepository(db).create({
        "uuid": doc_uuid,
        "original_name": name,
        "display_name": name,
        "stored_name": f"{doc_uuid}.bin",
        "file_path": f"uploads/{doc_uuid}.bin",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 128,
        "sha256_hash": sha or uuid.uuid4().hex * 2,
        "extracted_text": text,
        "owner_id": owner_id,
        "processing_status": "done",
    })


def add_safe_assessment(db: Session, doc, owner_id: int):
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


def auth(username: str):
    res = client.post("/auth/login", json={"username": username, "password": "Password123!"})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def create_and_activate_share(owner_headers, recipient_headers, doc_uuid, recipient_username):
    created = client.post(
        f"/documents/{doc_uuid}/shares", headers=owner_headers,
        json={"target_users": [recipient_username], "permission": "WRITE"},
    )
    assert created.status_code == 201, created.text
    share_id = created.json()[0]["id"] if isinstance(created.json(), list) else created.json()["shares"][0]["id"]
    report = client.get(f"/shares/direct/{share_id}/security-report", headers=recipient_headers)
    assert report.status_code == 200, report.text
    payload = report.json()
    activated = client.post(
        f"/shares/direct/{share_id}/activate", headers=recipient_headers,
        json={"assessment_id": payload["assessment_id"],
              "acknowledge_limited": bool(payload.get("limited_checks_ack_required"))},
    )
    assert activated.status_code == 200, activated.text
    return share_id


def test_recipient_personal_name_and_folder_do_not_mutate_owner_document(db_session: Session):
    owner = make_user(db_session, "personal_owner")
    recipient = make_user(db_session, "personal_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)
    body = "University semester fee receipt. Student fee payment receipt for the academic semester 2026. " * 2
    doc = make_doc(db_session, owner.id, "owner-canonical.pdf", text=body)
    add_safe_assessment(db_session, doc, owner.id)
    create_and_activate_share(owner_headers, recipient_headers, doc.uuid, recipient.username)

    owner_rename = DocumentSuggestion(
        document_id=doc.id, suggestion_type="rename", current_value="owner-canonical.pdf",
        suggested_value="Owner Private Name", reason="Owner-only proposal", confidence=0.9,
        status="pending", created_for_user_id=None,
    )
    recipient_rename = DocumentSuggestion(
        document_id=doc.id, suggestion_type="rename", current_value="owner-canonical.pdf",
        suggested_value="My Local Name", reason="Recipient personal view", confidence=0.9,
        status="pending", created_for_user_id=recipient.id,
    )
    recipient_route = DocumentSuggestion(
        document_id=doc.id, suggestion_type="route_folder", current_value="Unfiled",
        suggested_value="Academic/Receipts", reason="Use recipient's own folders", confidence=0.9,
        status="pending", created_for_user_id=recipient.id,
        evidence=json.dumps({"destination_category": "Academic", "destination_set_category": True}),
    )
    db_session.add_all([owner_rename, recipient_rename, recipient_route])
    db_session.commit()
    db_session.refresh(recipient_rename)
    db_session.refresh(recipient_route)

    recipient_suggestions = client.get(f"/suggestions?document_id={doc.id}", headers=recipient_headers)
    assert recipient_suggestions.status_code == 200, recipient_suggestions.text
    assert {row["suggested_value"] for row in recipient_suggestions.json()} == {"My Local Name", "Academic/Receipts"}
    assert "Owner Private Name" not in str(recipient_suggestions.json())

    accepted_name = client.post(f"/suggestions/{recipient_rename.id}/accept", headers=recipient_headers)
    assert accepted_name.status_code == 200, accepted_name.text
    accepted_route = client.post(f"/suggestions/{recipient_route.id}/accept", headers=recipient_headers)
    assert accepted_route.status_code == 200, accepted_route.text

    db_session.refresh(doc)
    assert doc.display_name == "owner-canonical.pdf"
    assert doc.folder_id is None
    assert doc.category is None

    pref = db_session.query(UserDocumentPreference).filter_by(user_id=recipient.id, document_id=doc.id).first()
    assert pref is not None and pref.display_name == "My Local Name"
    assert pref.folder_id is not None and pref.category == "Academic"
    recipient_folder = db_session.query(FolderModel).filter_by(id=pref.folder_id).first()
    assert recipient_folder is not None and recipient_folder.owner_id == recipient.id

    receiver_doc = client.get(f"/documents/{doc.uuid}", headers=recipient_headers)
    owner_doc = client.get(f"/documents/{doc.uuid}", headers=owner_headers)
    assert receiver_doc.status_code == owner_doc.status_code == 200
    assert receiver_doc.json()["display_name"] == "My Local Name"
    assert receiver_doc.json()["folder_id"] == pref.folder_id
    assert receiver_doc.json()["category"] == "Academic"
    assert owner_doc.json()["display_name"] == "owner-canonical.pdf"
    assert owner_doc.json()["folder_id"] is None
    assert owner_doc.json()["category"] is None


def test_recipient_duplicate_analysis_uses_its_accessible_library(db_session: Session):
    owner = make_user(db_session, "dupe_owner")
    recipient = make_user(db_session, "dupe_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)
    same_sha = "abc123" * 10 + "abcd"
    shared_doc = make_doc(db_session, owner.id, "owner-shared-copy.pdf", sha=same_sha, text="same document evidence text")
    recipient_doc = make_doc(db_session, recipient.id, "recipient-copy.pdf", sha=same_sha, text="same document evidence text")
    add_safe_assessment(db_session, shared_doc, owner.id)
    add_safe_assessment(db_session, recipient_doc, recipient.id)
    create_and_activate_share(owner_headers, recipient_headers, shared_doc.uuid, recipient.username)

    related = client.get(f"/documents/{shared_doc.uuid}/related", headers=recipient_headers)
    assert related.status_code == 200, related.text
    assert any(item["document_uuid"] == recipient_doc.uuid for item in related.json()["related_documents"])

    detail = client.get(f"/duplicates/{shared_doc.uuid}", headers=recipient_headers)
    assert detail.status_code == 200, detail.text
    assert any(item["document_uuid"] == recipient_doc.uuid for item in detail.json()["candidates"])


def test_recipient_summary_does_not_overwrite_owner_summary(db_session: Session):
    owner = make_user(db_session, "summary_owner")
    recipient = make_user(db_session, "summary_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)
    body = "This is a long shared document about university admission, payment receipts, fee confirmation, and semester administration. " * 3
    doc = make_doc(db_session, owner.id, "canonical-title.pdf", text=body)
    doc.summary = "Owner's existing summary"
    doc.key_topics = '["owner-topic"]'
    db_session.commit()
    add_safe_assessment(db_session, doc, owner.id)
    create_and_activate_share(owner_headers, recipient_headers, doc.uuid, recipient.username)

    response = client.post(f"/documents/{doc.uuid}/summary", headers=recipient_headers)
    assert response.status_code == 200, response.text
    assert response.json()["summary"]
    db_session.refresh(doc)
    assert doc.summary == "Owner's existing summary"
    assert doc.key_topics == '["owner-topic"]'


def test_access_lock_hides_shared_content_from_library_search_and_graph(db_session: Session):
    from backend.api.deps import search_service_instance

    owner = make_user(db_session, "lock_owner")
    recipient = make_user(db_session, "lock_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)
    body = "orchidrecipientlocktoken is a highly distinctive private search phrase in this shared file. " * 3
    doc = make_doc(db_session, owner.id, "locked-shared.pdf", text=body)
    add_safe_assessment(db_session, doc, owner.id)
    create_and_activate_share(owner_headers, recipient_headers, doc.uuid, recipient.username)
    doc.is_access_locked = 1
    doc.access_lock_hash = "configured-lock-hash"
    db_session.commit()
    search_service_instance.index_document(doc.id, body)

    library = client.get("/documents", headers=recipient_headers)
    assert library.status_code == 200, library.text
    row = next(item for item in library.json() if item["uuid"] == doc.uuid)
    assert row["summary"] is None
    assert row["extracted_text"] is None

    search = client.get("/search", params={"q": "orchidrecipientlocktoken"}, headers=recipient_headers)
    assert search.status_code == 200, search.text
    assert all(hit["document"]["uuid"] != doc.uuid for hit in search.json()["results"])

    suggest = client.get("/search/suggest", params={"prefix": "orchidrecipientlocktoken"}, headers=recipient_headers)
    assert suggest.status_code == 200, suggest.text
    assert suggest.json()["suggestions"] == []

    graph = client.get("/explorer/graph", headers=recipient_headers)
    assert graph.status_code == 200, graph.text
    assert all(node.get("details", {}).get("uuid") != doc.uuid for node in graph.json()["nodes"])



def test_recipient_group_analysis_is_personal_and_visible(db_session: Session):
    owner = make_user(db_session, "group_owner")
    recipient = make_user(db_session, "group_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)
    body = "College fee payment receipt. Semester fee payment confirmation for university fees. " * 4
    shared_doc = make_doc(db_session, owner.id, "College_Fee_Receipt.pdf", text=body)
    recipient_doc = make_doc(db_session, recipient.id, "College_Fee_Receipt.pdf", text=body)
    for doc in (shared_doc, recipient_doc):
        doc.category = "Financial"
        doc.category_source = "user_approved"
    db_session.commit()
    add_safe_assessment(db_session, shared_doc, owner.id)
    create_and_activate_share(owner_headers, recipient_headers, shared_doc.uuid, recipient.username)

    response = client.post("/suggestions/analyze-groups", headers=recipient_headers)
    assert response.status_code == 200, response.text
    receiver_groups = [
        row for row in response.json()
        if row["suggestion_type"] == "create_folder_group"
        and row.get("evidence", {}).get("v21_recipient_personal")
    ]
    assert receiver_groups, response.text
    group = receiver_groups[0]
    assert group["evidence"].get("v14_strong_group") is True
    assert shared_doc.id in group["evidence"].get("document_ids", [])

    visible = client.get("/suggestions", headers=recipient_headers)
    assert visible.status_code == 200, visible.text
    assert any(row["id"] == group["id"] for row in visible.json()), visible.text

    accepted = client.post(f"/suggestions/{group['id']}/accept", headers=recipient_headers)
    assert accepted.status_code == 200, accepted.text
    db_session.refresh(shared_doc)
    assert shared_doc.folder_id is None
    from backend.models.user_document_preference import UserDocumentPreference
    pref = db_session.query(UserDocumentPreference).filter_by(
        user_id=recipient.id, document_id=shared_doc.id
    ).first()
    assert pref is not None and pref.folder_id is not None
    assert db_session.query(FolderModel).filter_by(id=pref.folder_id, owner_id=recipient.id).first() is not None



def test_recipient_certificate_destination_and_grouping_are_personal(db_session: Session):
    owner = make_user(db_session, "certificate_owner")
    recipient = make_user(db_session, "certificate_recipient")
    owner_headers, recipient_headers = auth(owner.username), auth(recipient.username)

    # The source document is already in the owner's folder. That must not make
    # the receiver's analysis conclude that the receiver has nothing to file.
    sender_folder = FolderModel(name="SenderOnlyCertificatesFolder", owner_id=owner.id)
    db_session.add(sender_folder)
    db_session.flush()
    cert_text = "Certificate of completion awarded to the student for successful completion of a training program. " * 3
    shared_doc = make_doc(db_session, owner.id, "Marathwada_Mitra_Mandal_Certificate.jpg", text=cert_text)
    shared_doc.folder_id = sender_folder.id
    shared_doc.category = "Certificate"
    shared_doc.category_source = "classifier"

    recipient_doc = make_doc(db_session, recipient.id, "Course_Completion_Certificate.jpg", text=cert_text)
    recipient_doc.category = "Certificate"
    recipient_doc.category_source = "classifier"
    db_session.commit()
    add_safe_assessment(db_session, shared_doc, owner.id)
    create_and_activate_share(owner_headers, recipient_headers, shared_doc.uuid, recipient.username)

    analysis = client.post(
        f"/suggestions/analyze?document_id={shared_doc.id}", headers=recipient_headers
    )
    assert analysis.status_code == 200, analysis.text
    rows = analysis.json().get("suggestions", [])
    route = next((s for s in rows if s.get("suggestion_type") == "route_folder"), None)
    assert route is not None, analysis.text
    assert "SenderOnlyCertificatesFolder" not in route.get("suggested_value", "")
    assert route.get("suggested_value") == "Certificates"

    groups_response = client.post("/suggestions/analyze-groups", headers=recipient_headers)
    assert groups_response.status_code == 200, groups_response.text
    receiver_groups = [
        row for row in groups_response.json()
        if row.get("suggestion_type") == "create_folder_group"
        and row.get("evidence", {}).get("v21_recipient_personal")
        and shared_doc.id in row.get("evidence", {}).get("document_ids", [])
        and recipient_doc.id in row.get("evidence", {}).get("document_ids", [])
    ]
    assert receiver_groups, groups_response.text
    assert receiver_groups[0]["evidence"].get("suggested_folder_name") == "Certificates"

    db_session.refresh(shared_doc)
    assert shared_doc.folder_id == sender_folder.id
    recipient_suggestions = client.get(
        f"/suggestions?document_id={shared_doc.id}", headers=recipient_headers
    )
    assert recipient_suggestions.status_code == 200, recipient_suggestions.text
    assert any(row.get("suggestion_type") == "route_folder" for row in recipient_suggestions.json())



def test_recipient_duplicate_analysis_compares_independently_locked_received_documents(db_session: Session):
    owner_a = make_user(db_session, "dupe_shared_owner_a")
    owner_b = make_user(db_session, "dupe_shared_owner_b")
    recipient = make_user(db_session, "dupe_shared_recipient")
    owner_a_headers = auth(owner_a.username)
    owner_b_headers = auth(owner_b.username)
    recipient_headers = auth(recipient.username)
    same_sha = "receiver-shared-duplicate-" + ("x" * 48)
    shared_a = make_doc(db_session, owner_a.id, "shared-a.pdf", sha=same_sha, text="The same receipt payment confirmation document for semester fees. " * 3)
    shared_b = make_doc(db_session, owner_b.id, "shared-b.pdf", sha=same_sha, text="The same receipt payment confirmation document for semester fees. " * 3)
    add_safe_assessment(db_session, shared_a, owner_a.id)
    add_safe_assessment(db_session, shared_b, owner_b.id)
    create_and_activate_share(owner_a_headers, recipient_headers, shared_a.uuid, recipient.username)
    create_and_activate_share(owner_b_headers, recipient_headers, shared_b.uuid, recipient.username)

    # Each lock token is bound to a different shared document. A token for A must
    # never unlock B, but sending both valid tokens should let the receiver compare them.
    shared_a.is_access_locked = 1
    shared_a.access_lock_hash = "recipient-lock-hash-a"
    shared_b.is_access_locked = 1
    shared_b.access_lock_hash = "recipient-lock-hash-b"
    db_session.commit()
    token_a = JWTHandler.create_access_lock_token(shared_a.uuid, recipient.id, shared_a.access_lock_hash)
    token_b = JWTHandler.create_access_lock_token(shared_b.uuid, recipient.id, shared_b.access_lock_hash)
    recipient_headers = {
        **recipient_headers,
        "X-Access-Lock-Tokens": json.dumps({shared_a.uuid: token_a, shared_b.uuid: token_b}),
    }

    wrong_single_token = JWTHandler.create_access_lock_token(
        shared_a.uuid, recipient.id, shared_a.access_lock_hash
    )
    wrong_target = client.get(
        f"/duplicates/{shared_b.uuid}",
        headers={**recipient_headers, "X-Access-Lock-Tokens": "", "X-Access-Lock-Token": wrong_single_token},
    )
    assert wrong_target.status_code == 403, wrong_target.text

    result = client.get(f"/duplicates/{shared_a.uuid}", headers=recipient_headers)
    assert result.status_code == 200, result.text
    assert any(row.get("document_uuid") == shared_b.uuid for row in result.json().get("candidates", [])), result.text

    alerts = client.get("/duplicates/alerts", headers=recipient_headers)
    assert alerts.status_code == 200, alerts.text
    assert any(
        {row.get("document_uuid"), row.get("candidate_uuid")} == {shared_a.uuid, shared_b.uuid}
        for row in alerts.json().get("alerts", [])
    ), alerts.text


def test_recipient_group_analysis_and_accept_support_independent_document_lock_tokens(db_session: Session):
    owner_a = make_user(db_session, "group_shared_owner_a")
    owner_b = make_user(db_session, "group_shared_owner_b")
    recipient = make_user(db_session, "group_shared_recipient")
    owner_a_headers, owner_b_headers = auth(owner_a.username), auth(owner_b.username)
    recipient_headers = auth(recipient.username)
    cert_text = "Certificate of completion awarded to the student for successful completion of a training program. " * 3
    shared_a = make_doc(db_session, owner_a.id, "Course_A_Certificate.jpg", text=cert_text)
    shared_b = make_doc(db_session, owner_b.id, "Course_B_Certificate.jpg", text=cert_text)
    for doc in (shared_a, shared_b):
        doc.category = "Certificate"
        doc.category_source = "classifier"
        add_safe_assessment(db_session, doc, doc.owner_id)
    db_session.commit()
    create_and_activate_share(owner_a_headers, recipient_headers, shared_a.uuid, recipient.username)
    create_and_activate_share(owner_b_headers, recipient_headers, shared_b.uuid, recipient.username)

    # Only valid, per-document tokens may include locked received documents in a group.
    shared_a.is_access_locked = 1
    shared_a.access_lock_hash = "recipient-group-lock-a"
    shared_b.is_access_locked = 1
    shared_b.access_lock_hash = "recipient-group-lock-b"
    db_session.commit()
    token_a = JWTHandler.create_access_lock_token(shared_a.uuid, recipient.id, shared_a.access_lock_hash)
    token_b = JWTHandler.create_access_lock_token(shared_b.uuid, recipient.id, shared_b.access_lock_hash)
    scoped_headers = {
        **recipient_headers,
        "X-Access-Lock-Tokens": json.dumps({shared_a.uuid: token_a, shared_b.uuid: token_b}),
    }

    response = client.post("/suggestions/analyze-groups", headers=scoped_headers)
    assert response.status_code == 200, response.text
    group = next((row for row in response.json() if row.get("suggestion_type") == "create_folder_group"
                  and row.get("evidence", {}).get("v21_recipient_personal")
                  and set(row.get("evidence", {}).get("document_ids", [])) == {shared_a.id, shared_b.id}), None)
    assert group is not None, response.text

    accepted = client.post(f"/suggestions/{group['id']}/accept", headers=scoped_headers)
    assert accepted.status_code == 200, accepted.text
    db_session.refresh(shared_a)
    db_session.refresh(shared_b)
    assert shared_a.folder_id is None and shared_b.folder_id is None
    prefs = db_session.query(UserDocumentPreference).filter(
        UserDocumentPreference.user_id == recipient.id,
        UserDocumentPreference.document_id.in_([shared_a.id, shared_b.id]),
    ).all()
    assert len(prefs) == 2 and all(pref.folder_id for pref in prefs)
