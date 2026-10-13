import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from backend.main import app
from backend.database.connection import SessionLocal, Base, engine
from backend.database.repositories.user_repo import UserRepository
from backend.database.repositories.document_repo import DocumentRepository
from backend.database.repositories.suggestion_repo import SuggestionRepository
from backend.security.password import PasswordManager
from backend.models.suggestion import DocumentSuggestion

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


def _get_auth_headers(username: str, password: str = "Password123!"):
    res = client.post("/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _create_test_doc(db: Session, owner_id: int, original_name: str, extracted_text: str = ""):
    doc_repo = DocumentRepository(db)
    doc_uuid = str(uuid.uuid4())
    stored_name = f"{doc_uuid}_{original_name}"
    doc = doc_repo.create({
        "uuid": doc_uuid,
        "original_name": original_name,
        "stored_name": stored_name,
        "file_path": f"/storage/{stored_name}",
        "display_name": original_name,
        "file_type": "pdf",
        "mime_type": "application/pdf",
        "size_bytes": 2048,
        "sha256_hash": uuid.uuid4().hex,
        "owner_id": owner_id,
        "extracted_text": extracted_text,
        "category": "General"
    })
    return doc




def test_authenticated_library_analysis(db_session: Session):
    user = _create_test_user(db_session, "library_analyst")
    _create_test_doc(db_session, user.id, "clg_fee_rcpt_2026.pdf", "College fee receipt paid 2026")
    _create_test_doc(db_session, user.id, "dsa_assign_tree.pdf", "Data structure algorithm assignment tree")

    headers = _get_auth_headers(user.username)
    res = client.post("/suggestions/analyze", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "analyzed_count" in data
    assert data["analyzed_count"] == 2
    assert "category_counts" in data
    assert "suggestions" in data
    assert isinstance(data["suggestions"], list)
    assert len(data["suggestions"]) >= 2


def test_multi_user_isolation_and_idor_protection(db_session: Session):
    user_a = _create_test_user(db_session, "user_a_owner")
    user_b = _create_test_user(db_session, "user_b_attacker")

    doc_a = _create_test_doc(db_session, user_a.id, "clg_fee_rec.pdf", "College tuition fee receipt")
    
    # Generate suggestions for User A
    headers_a = _get_auth_headers(user_a.username)
    res_a = client.post("/suggestions/analyze", headers=headers_a)
    assert res_a.status_code == 200
    suggs_a = res_a.json()["suggestions"]
    assert len(suggs_a) > 0
    target_sugg_id = suggs_a[0]["id"]

    # User B attempts bulk accept on User A's suggestion ID
    headers_b = _get_auth_headers(user_b.username)
    res_b_accept = client.post("/suggestions/bulk-accept", json={"suggestion_ids": [target_sugg_id]}, headers=headers_b)
    assert res_b_accept.status_code == 200
    accepted = res_b_accept.json()
    assert len(accepted) == 0, "User B must not be able to accept User A's suggestion"

    # User B attempts bulk reject on User A's suggestion ID
    res_b_reject = client.post("/suggestions/bulk-reject", json={"suggestion_ids": [target_sugg_id]}, headers=headers_b)
    assert res_b_reject.status_code == 200
    rejected = res_b_reject.json()
    assert len(rejected) == 0, "User B must not be able to reject User A's suggestion"

    # Verify User A's suggestion is still pending
    s_repo = SuggestionRepository(db_session)
    s_db = s_repo.get_by_id(target_sugg_id)
    assert s_db.status == "pending"


def test_bulk_accept_and_bulk_reject(db_session: Session):
    user = _create_test_user(db_session, "bulk_user")
    _create_test_doc(db_session, user.id, "clg_fees_receipt.pdf", "College tuition fees receipt")
    _create_test_doc(db_session, user.id, "dsa_hw_report.pdf", "Data structure algorithm report")

    headers = _get_auth_headers(user.username)
    res_analysis = client.post("/suggestions/analyze", headers=headers)
    assert res_analysis.status_code == 200
    suggs = res_analysis.json()["suggestions"]
    assert len(suggs) >= 2

    accept_id = suggs[0]["id"]
    reject_id = suggs[1]["id"]

    # Bulk Accept
    res_bulk_accept = client.post("/suggestions/bulk-accept", json={"suggestion_ids": [accept_id]}, headers=headers)
    assert res_bulk_accept.status_code == 200
    accepted_items = res_bulk_accept.json()
    assert len(accepted_items) == 1
    assert accepted_items[0]["id"] == accept_id
    assert accepted_items[0]["status"] == "accepted"

    # Bulk Reject
    res_bulk_reject = client.post("/suggestions/bulk-reject", json={"suggestion_ids": [reject_id]}, headers=headers)
    assert res_bulk_reject.status_code == 200
    rejected_items = res_bulk_reject.json()
    assert len(rejected_items) == 1
    assert rejected_items[0]["id"] == reject_id
    assert rejected_items[0]["status"] == "rejected"


def test_deduplication_across_repeated_analysis(db_session: Session):
    user = _create_test_user(db_session, "repeat_analyst")
    _create_test_doc(db_session, user.id, "proj_report_dsa.pdf", "Project report for DSA assignment")

    headers = _get_auth_headers(user.username)
    res1 = client.post("/suggestions/analyze", headers=headers)
    assert res1.status_code == 200
    count1 = len(res1.json()["suggestions"])

    res2 = client.post("/suggestions/analyze", headers=headers)
    assert res2.status_code == 200
    count2 = len(res2.json()["suggestions"])

    assert count1 == count2, "Repeated library analysis must not duplicate pending suggestions"


def test_empty_library_analysis(db_session: Session):
    user = _create_test_user(db_session, "empty_analyst")
    headers = _get_auth_headers(user.username)

    res = client.post("/suggestions/analyze", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["analyzed_count"] == 0
    assert data["suggestions"] == []
