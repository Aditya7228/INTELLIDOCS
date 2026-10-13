from pathlib import Path
import ast
import io
import zipfile

from PIL import Image

from backend.security.path_guard import PathGuard, SecurityError
from backend.security.static_analyzer import StaticSecurityAnalyzer, FindingDetail
from backend.security.unified_risk_engine import UnifiedRiskEngine

ROOT = Path(__file__).resolve().parents[1]


def test_gap_hunt_path_guard_sibling_prefix_rejected():
    root = (ROOT / ".gap_hunt_test_storage").resolve()
    allowed = root / "uploads"
    guard = PathGuard(storage_root=root)
    guard._verify_bounds(allowed / "safe.pdf", allowed)
    try:
        guard._verify_bounds(root / "uploads_evil" / "evil.pdf", allowed)
    except SecurityError:
        pass
    else:
        raise AssertionError("Sibling-prefix path was accepted")


def test_gap_hunt_path_guard_traversal_rejected():
    root = (ROOT / ".gap_hunt_test_storage").resolve()
    allowed = root / "uploads"
    guard = PathGuard(storage_root=root)
    try:
        guard._verify_bounds((allowed / ".." / "secret.txt").resolve(), allowed)
    except SecurityError:
        pass
    else:
        raise AssertionError("Traversal path was accepted")


def test_gap_hunt_validation_failure_quarantines():
    finding = FindingDetail(
        check_name="file_validation",
        title="Upload validation failed",
        severity="HIGH",
        finding_type="upload_validation_failed",
        technical_evidence="Unsupported extension",
        potential_harm="Not eligible for normal processing",
    )
    result = UnifiedRiskEngine.evaluate(
        findings=[finding],
        scanner_available=True,
        scanner_status="PASSED",
        pii_types=[],
        ocr_text="",
    )
    assert result.verdict == "SUSPICIOUS"
    assert result.risk_level == "SUSPICIOUS"


def test_gap_hunt_version_route_is_security_gated():
    path = ROOT / "backend/api/documents.py"
    source = path.read_text(encoding="utf-8-sig", errors="replace")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "upload_new_version":
            route = ast.get_source_segment(source, node) or ""
            assert "SecurityAssessmentService" in route
            assert "run_assessment" in route
            assert 'assessment.verdict in ["SUSPICIOUS", "BLOCKED"]' in route
            assert route.find("run_assessment") < route.find("process_and_store_upload")
            assert "owner_id=parent_doc.owner_id" in route
            return
    raise AssertionError("upload_new_version() route not found")


def test_gap_hunt_quarantine_actions_preserve_owner():
    source = (ROOT / "backend/api/documents.py").read_text(encoding="utf-8-sig", errors="replace")
    assert source.count("owner_id=assessment.owner_id") >= 2


def test_gap_hunt_document_sort_is_allowlisted():
    source = (ROOT / "backend/api/documents.py").read_text(encoding="utf-8-sig", errors="replace")
    assert "DOCUMENT_SORT_FIELDS =" in source
    assert "DOCUMENT_SORT_FIELDS.get(sort_by" in source
    assert "getattr(DocumentModel, sort_by" not in source


def test_gap_hunt_docx_core_structure_is_checked(tmp_path):
    path = tmp_path / "incomplete.docx"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("random.txt", "hello")
    findings = StaticSecurityAnalyzer._analyze_docx_structure(str(path), path.read_bytes())
    assert any(f.finding_type == "invalid_ooxml_structure" for f in findings)


def test_gap_hunt_image_structure_is_checked():
    out = io.BytesIO()
    Image.new("RGB", (4, 4)).save(out, format="PNG")
    good = StaticSecurityAnalyzer._analyze_image_structure(out.getvalue())
    bad = StaticSecurityAnalyzer._analyze_image_structure(b"not an image")
    assert not any(f.finding_type == "invalid_image_structure" for f in good)
    assert any(f.finding_type == "invalid_image_structure" for f in bad)
