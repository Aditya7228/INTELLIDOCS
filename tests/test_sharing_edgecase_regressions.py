"""Regression coverage for two confirmed IntelliDocs sharing edge cases.

These tests intentionally fail against the current implementation. They are tests only;
they do not alter application code or test fixtures outside this file.
"""
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import func

from backend.main import app
from backend.database.connection import Base, SessionLocal, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.models.document_share import DocumentShare
from backend.models.group import GroupDocumentShare
from backend.models.security_assessment import SecurityAssessmentModel
from backend.security.password import PasswordManager

client = TestClient(app)
PASSWORD = "DiagnosticOnly123!"


def _make_user(db, prefix):
    suffix = uuid.uuid4().hex[:10]
    username = f"{prefix}_{suffix}"
    return UserRepository(db).create_user(
        username=username,
        email=f"{username}@example.com",
        password_hash=PasswordManager.hash_password(PASSWORD),
        role="user",
    )


def _login(user):
    response = client.post(
        "/auth/login",
        json={"username": user.username, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _make_safe_document(db, owner):
    token = uuid.uuid4().hex
    doc_uuid = f"sharing-regression-{token}"
    doc = DocumentRepository(db).create({
        "uuid": doc_uuid,
        "original_name": f"regression-{token}.pdf",
        "stored_name": f"{doc_uuid}.pdf",
        "file_path": f"uploads/{doc_uuid}.pdf",
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 15000,
        "sha256_hash": uuid.uuid4().hex * 2,
        "owner_id": owner.id,
        "processing_status": "done",
    })

    db.add(SecurityAssessmentModel(
        quarantine_uuid=str(uuid.uuid4()),
        document_id=doc.id,
        owner_id=owner.id,
        original_name=doc.original_name,
        stored_quarantine_name=f"{doc_uuid}.pdf",
        file_type="pdf",
        mime_type="application/pdf",
        size_bytes=doc.size_bytes,
        sha256_hash=doc.sha256_hash,
        risk_score=0,
        risk_level="LOW RISK",
        confidence="HIGH",
        verdict="SAFE",
        data_sensitivity="public",
        pii_detected=0,
        scanner_status="AVAILABLE",
        check_states_json="{}",
        findings_json="[]",
        why_explanations_json="[]",
        potential_harms_json="[]",
        recommended_action="Available checks completed",
        quarantine_status="PROMOTED",
    ))
    db.commit()
    db.refresh(doc)
    return doc


def _make_direct_and_group_share_id_collision(db, doc, owner, direct_user, group_id):
    direct_max = db.query(func.max(DocumentShare.id)).scalar() or 0
    group_max = db.query(func.max(GroupDocumentShare.id)).scalar() or 0
    collision_id = max(direct_max, group_max) + 1
    now = datetime.now(timezone.utc).isoformat()

    db.add_all([
        DocumentShare(
            id=collision_id,
            document_id=doc.id,
            owner_id=owner.id,
            target_user_id=direct_user.id,
            permission="READ",
            active=1,
            created_at=now,
            updated_at=now,
        ),
        GroupDocumentShare(
            id=collision_id,
            document_id=doc.id,
            owner_id=owner.id,
            group_id=group_id,
            permission="READ",
            active=1,
            created_at=now,
            updated_at=now,
        ),
    ])
    db.commit()
    return collision_id


def _create_group_with_member(owner_headers, member_username):
    response = client.post(
        "/groups",
        headers=owner_headers,
        json={
            "name": f"sharing_regression_group_{uuid.uuid4().hex[:8]}",
            "member_usernames": [member_username],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_ambiguous_legacy_revoke_does_not_revoke_either_share():
    """The legacy unqualified DELETE must not guess when IDs collide."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        owner = _make_user(db, "reg_revoke_owner")
        direct_user = _make_user(db, "reg_revoke_direct")
        group_member = _make_user(db, "reg_revoke_group")
        owner_headers = _login(owner)
        group_id = _create_group_with_member(owner_headers, group_member.username)
        doc = _make_safe_document(db, owner)
        collision_id = _make_direct_and_group_share_id_collision(
            db, doc, owner, direct_user, group_id
        )

        response = client.delete(
            f"/documents/{doc.uuid}/shares/{collision_id}",
            headers=owner_headers,
        )

        # Safe behavior: reject ambiguous source rather than revoke the wrong grant.
        assert response.status_code == 409, (
            "An unqualified revoke with colliding direct/group IDs must return 409; "
            f"got {response.status_code}: {response.text}"
        )

        db.expire_all()
        direct = db.query(DocumentShare).filter_by(
            id=collision_id, document_id=doc.id
        ).one()
        group_share = db.query(GroupDocumentShare).filter_by(
            id=collision_id, document_id=doc.id
        ).one()
        assert direct.active == 1
        assert group_share.active == 1
    finally:
        db.close()


def test_source_qualified_group_revoke_preserves_colliding_direct_share():
    """A source-qualified revoke should affect only the requested share table."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        owner = _make_user(db, "reg_source_owner")
        direct_user = _make_user(db, "reg_source_direct")
        group_member = _make_user(db, "reg_source_group")
        owner_headers = _login(owner)
        group_id = _create_group_with_member(owner_headers, group_member.username)
        doc = _make_safe_document(db, owner)
        collision_id = _make_direct_and_group_share_id_collision(
            db, doc, owner, direct_user, group_id
        )

        response = client.delete(
            f"/documents/{doc.uuid}/shares/{collision_id}?source=group",
            headers=owner_headers,
        )
        assert response.status_code == 200, response.text

        db.expire_all()
        direct = db.query(DocumentShare).filter_by(
            id=collision_id, document_id=doc.id
        ).one()
        group_share = db.query(GroupDocumentShare).filter_by(
            id=collision_id, document_id=doc.id
        ).one()
        assert direct.active == 1, "Source=group must not deactivate the direct share."
        assert group_share.active == 0, "Source=group must deactivate the group share."
    finally:
        db.close()


def test_invalid_later_recipient_does_not_leave_partial_share():
    """Validate every recipient before creating any share in a multi-share request."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    verify_db = None
    try:
        owner = _make_user(db, "reg_multi_owner")
        valid_recipient = _make_user(db, "reg_multi_valid")
        owner_headers = _login(owner)
        doc = _make_safe_document(db, owner)
        invalid_username = f"missing_{uuid.uuid4().hex}"

        response = client.post(
            f"/documents/{doc.uuid}/shares",
            headers=owner_headers,
            json={
                "target_users": [valid_recipient.username, invalid_username],
                "permission": "READ",
            },
        )
        assert response.status_code == 400, response.text

        verify_db = SessionLocal()
        active_rows = verify_db.query(DocumentShare).filter(
            DocumentShare.document_id == doc.id,
            DocumentShare.target_user_id == valid_recipient.id,
            DocumentShare.active == 1,
        ).all()
        assert not active_rows, (
            "The multi-recipient request failed but a valid recipient's share persisted."
        )
    finally:
        if verify_db:
            verify_db.close()
        db.close()
