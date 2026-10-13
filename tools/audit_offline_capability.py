from pathlib import Path
from datetime import datetime
import re

ROOT = Path(__file__).resolve().parents[1]
SCAN_DIRS = [ROOT / "backend", ROOT / "frontend"]

patterns = {
    "HTTP libraries": re.compile(r"\b(?:requests|httpx|urllib3|aiohttp)\b", re.I),
    "URL literals": re.compile(r"https?://", re.I),
    "SMTP": re.compile(r"\bsmtplib\b|\bSMTP\b", re.I),
    "Browser fetch": re.compile(r"\bfetch\s*\(", re.I),
    "WebSocket": re.compile(r"\b(?:WebSocket|websocket)\b", re.I),
    "Socket": re.compile(r"\bsocket\b", re.I),
    "Model download/load": re.compile(r"(?:from_pretrained|download|snapshot_download|hf_hub)", re.I),
}

findings = []

for base in SCAN_DIRS:
    if not base.exists():
        continue

    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts:
            continue
        if path.suffix.lower() not in {".py", ".js", ".html", ".css"}:
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for label, pattern in patterns.items():
            matches = list(pattern.finditer(text))
            if matches:
                lines = text.splitlines()
                line_numbers = []
                for m in matches[:5]:
                    line_numbers.append(text.count("\n", 0, m.start()) + 1)

                findings.append({
                    "type": label,
                    "file": str(path.relative_to(ROOT)),
                    "lines": ", ".join(map(str, line_numbers)),
                })

report = []
report.append("# IntelliDocs Offline Capability Audit")
report.append("")
report.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
report.append("")
report.append("## Purpose")
report.append("This is a code-level dependency audit. It does not claim that the entire application was tested under complete network isolation.")
report.append("")
report.append("## Classification guidance")
report.append("")
report.append("- FULL OFFLINE: functionality is designed around local resources and has no required network dependency.")
report.append("- MOSTLY OFFLINE: core operation is local, but optional/external functionality may use the network.")
report.append("- NETWORK REQUIRED: the functionality depends on an external service or network connection.")
report.append("- OPTIONAL NETWORK: local operation exists, while a network enhancement such as email may be available.")
report.append("- UNKNOWN: code inspection alone is insufficient.")
report.append("")
report.append("## Detected Potential Network/Remote Dependencies")
report.append("")

if findings:
    report.append("| Type | File | Lines |")
    report.append("|---|---|---:|")
    for f in findings:
        report.append(f"| {f['type']} | `{f['file']}` | {f['lines']} |")
else:
    report.append("No obvious network-related patterns were detected in the scanned backend/frontend source.")

report.append("")
report.append("## Runtime verification still required")
report.append("")
report.append("Complete network isolation testing should be performed separately before making a claim of full offline operation.")
report.append("")
report.append("Suggested local checks:")
report.append("")
report.append("```powershell")
report.append("python -m pytest -q")
report.append("python -m compileall backend")
report.append("git diff --check")
report.append("```")
report.append("")

out = ROOT / "OFFLINE_CAPABILITY.md"
out.write_text("\n".join(report), encoding="utf-8")
print(f"Created: {out}")
print(f"Potential dependency findings: {len(findings)}")
