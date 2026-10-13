import pytest
import os
import zipfile
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.connection import SessionLocal, engine, Base
from backend.models.user import User
from backend.models.document import DocumentModel
from backend.models.security_assessment import SecurityAssessmentModel
from backend.security.malware_scanner import MalwareScannerAdapter, ScanResult
from backend.security.quarantine_manager import QuarantineManager
from backend.security.security_assessment_service import SecurityAssessmentService
from backend.security.unified_risk_engine import UnifiedRiskEngine, FindingDetail

@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    return client

@pytest.fixture
def auth_headers(client):
    # Register and login test user
    client.post("/auth/register", json={"username": "sec_user", "email": "sec@test.com", "password": "password123"})
    res = client.post("/auth/login", json={"username": "sec_user", "password": "password123"})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def auth_headers_user2(client):
    client.post("/auth/register", json={"username": "sec_user2", "email": "sec2@test.com", "password": "password123"})
    res = client.post("/auth/login", json={"username": "sec_user2", "password": "password123"})
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# 1. Normal PDF -> SAFE / LOW RISK
def test_upload_normal_pdf(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res = client.post(
        "/documents/upload",
        files={"file": ("normal.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    data = res.json()
    assert "security_assessment" in data
    sec = data["security_assessment"]
    assert sec["verdict"] == "SAFE"
    assert sec["risk_level"] == "LOW RISK"
    assert sec["risk_score"] < 30
    assert data["uuid"] is not None


# 2. Normal DOCX -> SAFE / LOW RISK
def test_upload_normal_docx(client, auth_headers, tmp_path):
    docx_file = tmp_path / "sample.docx"
    with zipfile.ZipFile(docx_file, 'w') as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document></w:document>')

    with open(docx_file, "rb") as f:
        bytes_data = f.read()

    res = client.post(
        "/documents/upload",
        files={"file": ("sample.docx", bytes_data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        headers=auth_headers
    )
    assert res.status_code == 201
    sec = res.json()["security_assessment"]
    assert sec["verdict"] == "SAFE"
    assert sec["risk_score"] < 30


# 3. PDF with harmless external URL -> NOT automatically malicious
def test_upload_pdf_with_url(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Action /S /URI /URI (https://example.com/docs) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res = client.post(
        "/documents/upload",
        files={"file": ("url_doc.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    sec = res.json()["security_assessment"]
    assert sec["verdict"] == "SAFE"
    assert sec["risk_score"] < 30
    assert any("external URL" in w for w in sec["why_explanations"])


# 4. Sensitive document with PII -> Data Sensitivity HIGH, but Security Risk LOW / SAFE
def test_upload_pii_sensitive_pdf(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< >>\nstream\nAadhaar: 9999-8888-7777 SSN: 000-12-3456 Bank Account: 123456789012\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res = client.post(
        "/documents/upload",
        files={"file": ("sensitive.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    sec = res.json()["security_assessment"]
    assert sec["verdict"] == "SAFE"
    assert sec["risk_level"] == "LOW RISK"
    assert sec["data_sensitivity"] in ["confidential", "restricted"]


# 5. MIME mismatch -> Low risk anomaly, NOT automatically malicious
def test_upload_mime_mismatch(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< >>\nendobj\ntrailer\n<< >>\n%%EOF"
    res = client.post(
        "/documents/upload",
        files={"file": ("mismatch.png", pdf_content, "image/png")},
        headers=auth_headers
    )
    assert res.status_code == 201
    sec = res.json()["security_assessment"]
    assert sec["verdict"] == "SAFE"
    assert sec["risk_score"] < 30


# 6. Embedded suspicious object (PDF /Launch action) -> SUSPICIOUS / QUARANTINED
def test_upload_pdf_with_launch_action(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res = client.post(
        "/documents/upload",
        files={"file": ("suspicious_launch.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    data = res.json()
    sec = data["security_assessment"]
    assert sec["verdict"] == "SUSPICIOUS"
    assert sec["risk_score"] >= 30
    assert data["uuid"] is None  # Blocked from normal document library!


# 7. Confirmed malware signature (EICAR) -> MALICIOUS / BLOCKED
def test_upload_confirmed_malware_eicar(client, auth_headers):
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    res = client.post(
        "/documents/upload",
        files={"file": ("eicar_test.pdf", eicar_bytes, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    data = res.json()
    sec = data["security_assessment"]
    assert sec["verdict"] == "BLOCKED"
    assert sec["risk_level"] == "MALICIOUS"
    assert sec["risk_score"] >= 90
    assert data["uuid"] is None


# 8. Archive with executable child -> SUSPICIOUS / HIGH RISK quarantine
def test_upload_archive_with_exe_child(client, auth_headers, tmp_path):
    zip_path = tmp_path / "archive_payload.zip"
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("read_me.txt", "Hello world")
        zf.writestr("malicious_setup.exe", b"MZ90000000000")

    with open(zip_path, "rb") as f:
        bytes_data = f.read()

    res = client.post(
        "/documents/upload",
        files={"file": ("archive_payload.zip", bytes_data, "application/pdf")},
        headers=auth_headers
    )
    assert res.status_code == 201
    sec = res.json()["security_assessment"]
    assert sec["verdict"] == "SUSPICIOUS"
    assert sec["risk_score"] >= 30


# 9. Scanner unavailable state -> Honest status UNAVAILABLE + MEDIUM confidence
def test_scanner_unavailable_handling():
    eval_res = UnifiedRiskEngine.evaluate(
        findings=[],
        scanner_available=False,
        scanner_status="UNAVAILABLE",
        pii_types=[],
        ocr_text="Clean document text"
    )
    assert eval_res.scanner_status == "UNAVAILABLE"
    assert eval_res.confidence == "MEDIUM"
    assert eval_res.verdict == "SAFE"
    assert any("Malware scanner was unavailable" in w for w in eval_res.why_explanations)


# 10. Manual quarantine list endpoint
def test_list_quarantine_endpoint(client, auth_headers):
    # Upload suspicious doc to populate quarantine
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /Launch /F (calc.exe) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    client.post(
        "/documents/upload",
        files={"file": ("launch_calc.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )

    res = client.get("/documents/quarantine/list", headers=auth_headers)
    assert res.status_code == 200
    items = res.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    assert any(i["original_name"] == "launch_calc.pdf" for i in items)


# 11. Multi-user security report isolation -> User B cannot access User A's private security report
def test_multi_user_security_report_isolation(client, auth_headers, auth_headers_user2):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /Launch /F (calc.exe) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res1 = client.post(
        "/documents/upload",
        files={"file": ("private_user1.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    sec_uuid = res1.json()["security_assessment"]["quarantine_uuid"]

    # User 1 accesses report -> OK
    res_ok = client.get(f"/documents/security/report/{sec_uuid}", headers=auth_headers)
    assert res_ok.status_code == 200

    # User 2 accesses User 1's report -> 403 FORBIDDEN
    res_forbidden = client.get(f"/documents/security/report/{sec_uuid}", headers=auth_headers_user2)
    assert res_forbidden.status_code == 403


# 12. Promote SUSPICIOUS quarantined file manually
def test_manual_promote_suspicious_file(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res_upload = client.post(
        "/documents/upload",
        files={"file": ("js_doc.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    q_uuid = res_upload.json()["security_assessment"]["quarantine_uuid"]

    # Promote
    res_promote = client.post(f"/documents/quarantine/{q_uuid}/promote", headers=auth_headers)
    assert res_promote.status_code == 200
    assert res_promote.json()["status"] == "PROMOTED"
    assert res_promote.json()["document_uuid"] is not None


# 13. Forbidden promotion for confirmed MALICIOUS / BLOCKED file
def test_forbidden_promote_malicious_file(client, auth_headers):
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    res_upload = client.post(
        "/documents/upload",
        files={"file": ("eicar_blocked.pdf", eicar_bytes, "application/pdf")},
        headers=auth_headers
    )
    q_uuid = res_upload.json()["security_assessment"]["quarantine_uuid"]

    # Attempt promote -> 400 Bad Request
    res_promote = client.post(f"/documents/quarantine/{q_uuid}/promote", headers=auth_headers)
    assert res_promote.status_code == 400
    assert "Cannot promote confirmed MALICIOUS file" in res_promote.json()["detail"]


# 14. Delete quarantined file safely
def test_delete_quarantined_file(client, auth_headers):
    pdf_content = b"%PDF-1.5\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    res_upload = client.post(
        "/documents/upload",
        files={"file": ("delete_me.pdf", pdf_content, "application/pdf")},
        headers=auth_headers
    )
    q_uuid = res_upload.json()["security_assessment"]["quarantine_uuid"]

    res_del = client.delete(f"/documents/quarantine/{q_uuid}", headers=auth_headers)
    assert res_del.status_code == 200
    assert res_del.json()["status"] == "DELETED"
