import pytest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.algorithms.graph import DocumentGraph, RelationType
from backend.core.document_service import DocumentService
from backend.api.deps import document_service_instance

def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["app"] == "IntelliDocs API"

def test_auth_register_login_refresh_flow():
    with TestClient(app) as client:
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        email = f"{username}@example.com"
        password = "SecurePassword123!"

        # 1. Register
        reg_res = client.post("/auth/register", json={
            "username": username,
            "email": email,
            "password": password
        })
        assert reg_res.status_code == 201
        user_data = reg_res.json()
        assert user_data["username"] == username
        assert user_data["email"] == email

        # 2. Login
        login_res = client.post("/auth/login", json={
            "username": username,
            "password": password
        })
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        assert "refresh_token" in token_data

        # 3. Refresh Token
        refresh_token = token_data["refresh_token"]
        refresh_res = client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert refresh_res.status_code == 200
        new_token_data = refresh_res.json()
        assert "access_token" in new_token_data
        assert "refresh_token" in new_token_data

        # 4. Re-using revoked old refresh token should fail
        revoked_res = client.post("/auth/refresh", json={
            "refresh_token": refresh_token
        })
        assert revoked_res.status_code == 401

def test_document_graph_deletion():
    graph = DocumentGraph()
    graph.add_edge(1, 2, RelationType.EXACT_DUPLICATE, 1.0)
    graph.add_edge(1, 3, RelationType.POSSIBLE_NEAR_DUPLICATE, 0.8)
    graph.add_edge(2, 3, RelationType.RELATED, 0.5)

    assert len(graph.get_neighbors(1)) == 2
    assert len(graph.get_neighbors(2)) == 2

    # Remove node 1
    graph.remove_node(1)

    assert graph.get_neighbors(1) == []
    assert not any(e.target_id == 1 for e in graph.get_neighbors(2))
    assert not any(e.target_id == 1 for e in graph.get_neighbors(3))

def test_document_service_import_and_instance():
    assert document_service_instance is not None
    assert isinstance(document_service_instance, DocumentService)

# ---------------------------------------------------------------------------
# FileValidator / upload-validation fix regression tests
# ---------------------------------------------------------------------------

def test_file_validator_class_attribute_exists():
    """FileValidator.ALLOWED_MIME_TYPES must be accessible as a class attribute."""
    from backend.security.file_validator import FileValidator
    assert hasattr(FileValidator, "ALLOWED_MIME_TYPES"), (
        "FileValidator.ALLOWED_MIME_TYPES is not a class attribute; "
        "document_service.py will crash at upload time."
    )
    assert "application/pdf" in FileValidator.ALLOWED_MIME_TYPES

def test_file_validator_pdf_accepted():
    from backend.security.file_validator import FileValidator
    pdf_bytes = b"%PDF-1.4 minimal"
    result = FileValidator.validate_upload("test.pdf", "application/pdf", pdf_bytes)
    assert result.valid is True
    assert result.mime_type == "application/pdf"
    assert result.file_type == "pdf"
    # class-attribute lookup must also succeed (replicates document_service line 57)
    ext = FileValidator.ALLOWED_MIME_TYPES[result.mime_type]
    assert ext == "pdf"

def test_file_validator_rejects_empty():
    from backend.security.file_validator import FileValidator
    result = FileValidator.validate_upload("test.pdf", "application/pdf", b"")
    assert result.valid is False
    assert "empty" in result.error.lower()

def test_file_validator_rejects_bad_extension():
    from backend.security.file_validator import FileValidator
    result = FileValidator.validate_upload("evil.exe", "application/pdf", b"%PDF-1.4 x")
    assert result.valid is False

def test_upload_pdf_endpoint():
    """End-to-end upload via POST /documents/upload with a minimal valid PDF."""
    import io
    from backend.security.file_validator import FileValidator

    MINIMAL_PDF = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
        b"xref\n0 4\n0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"trailer<</Size 4/Root 1 0 R>>\n"
        b"startxref\n190\n%%EOF"
    )

    # Pre-validate the bytes ourselves so test failure is clearly scoped
    pre = FileValidator.validate_upload("upload_test.pdf", "application/pdf", MINIMAL_PDF)
    assert pre.valid, f"FileValidator rejected the test PDF: {pre.error}"

    with TestClient(app) as client:
        # Register + login to get token
        client.post("/auth/register", json={
            "username": "upload_test_user",
            "email": "upload_test_user@example.com",
            "password": "Upload1234!"
        })
        login_res = client.post("/auth/login", json={
            "username": "upload_test_user",
            "password": "Upload1234!"
        })
        token = login_res.json().get("access_token", "")
        assert token, "Could not obtain access token for upload test"

        response = client.post(
            "/documents/upload",
            files={"file": ("upload_test.pdf", io.BytesIO(MINIMAL_PDF), "application/pdf")},
            headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 201, (
        f"Upload returned {response.status_code}: {response.text}"
    )
    data = response.json()
    assert data.get("file_type") == "pdf"
    assert data.get("uuid") is not None
    print(f"\n  Upload OK — uuid={data['uuid']} category={data.get('category')} sensitivity={data.get('sensitivity')}")

