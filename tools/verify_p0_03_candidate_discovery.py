from pathlib import Path
import ast
import sys

root = Path.cwd()
service = root / "backend" / "core" / "duplicate_service.py"
if not service.exists():
    raise SystemExit("SERVICE_NOT_FOUND")
text = service.read_text(encoding="utf-8")

required = [
    "# --- P0_03_CANDIDATE_DISCOVERY",
    "def _duplicate_p0_03_discover_candidate_ids",
    "_duplicate_p0_03_discover_candidate_ids(",
    "DuplicateService.analyze_all_candidates = _duplicate_v11_analyze_all_candidates",
]
for needle in required:
    if needle not in text:
        raise SystemExit(f"MISSING:{needle}")

start = text.index("# --- DUPLICATE_POLICY_V11_20261008_SERVICE")
endtok = "# --- END DUPLICATE_POLICY_V11_20261008_SERVICE ----------------------------"
end = text.index(endtok, start) + len(endtok)
v11 = text[start:end]

# The active V11 analyzer must not delegate to the legacy V9/V10 analyzer.
if "_DUPLICATE_V11_ORIGINAL_ANALYZE_ALL_CANDIDATES" in v11:
    raise SystemExit("LEGACY_ANALYZE_DELEGATION_STILL_ACTIVE")
if "repo.list_user_documents(owner_id=owner_id, limit=100)" in v11:
    raise SystemExit("BROAD_ALL_DOCUMENT_FALLBACK_PRESENT_IN_ACTIVE_V11")

ast.parse(text)
print("P0_03_CANDIDATE_DISCOVERY_VERIFY_OK")
print("ACTIVE_V11_SEPARATES_DISCOVERY=YES")
print("LEGACY_V9_V10_ANALYZE_DELEGATION=NO")
print("BROAD_ALL_DOCUMENT_FALLBACK_IN_ACTIVE_V11=NO")
