from pathlib import Path
import sys

app = Path("frontend/app.js")
if not app.is_file():
    raise SystemExit("FAIL: frontend/app.js not found. Run from IntelliDocs project root.")
source = app.read_text(encoding="utf-8-sig")
start = source.find("async function initDuplicatesPage()")
end = source.find("async function inspectSelectedDuplicates()", start)
if start < 0 or end < 0:
    raise SystemExit("FAIL: could not isolate initDuplicatesPage().")
block = source[start:end]
checks = {
    "filteredAlerts declared once in initDuplicatesPage": block.count("const filteredAlerts =") == 1,
    "candidate array safely defaults to empty": "const alertCandidates = (alertData && Array.isArray(alertData.alerts)) ? alertData.alerts : [];" in block,
    "empty-state test occurs after declaration": block.find("const filteredAlerts =") < block.find("if (filteredAlerts.length === 0)"),
    "badge reads the same visible filtered count": "badgeD.innerText = String(filteredAlerts.length);" in block,
    "badge does not use stale API count": "badgeD.innerText = alertData.alert_count;" not in block,
    "redundant empty test removed from rendering branch": "filteredAlerts.length === 0 ?" not in block,
}
for name, ok in checks.items():
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
if not all(checks.values()):
    raise SystemExit(1)
print("P0_06_FRONTEND_ALERT_SCOPE_VERIFY_OK")
