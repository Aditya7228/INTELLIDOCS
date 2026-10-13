import os
import zipfile
import tarfile
from typing import List
from backend.security.static_analyzer import FindingDetail

class ArchiveAnalyzer:
    """
    Analyzes archive containers for nested executable payloads,
    recursion limits, and zip bomb expansion ratio protection.
    """

    MAX_FILES = 1000
    MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB
    MAX_EXPANSION_RATIO = 100.0  # 100x compression ratio limit
    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".jar", ".js", ".py", ".sh", ".cpl", ".pif", ".hta"
    }

    @classmethod
    def analyze_archive(cls, file_path: str, mime_type: str, file_bytes: bytes) -> List[FindingDetail]:
        findings = []

        # Only process if archive mime or file signature
        is_zip = file_bytes.startswith(b"PK\x03\x04")
        if not is_zip:
            return findings

        # Skip standard docx container checks here as docx is inspected by static_analyzer
        if mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            return findings

        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                infolist = zf.infolist()
                
                # 1. Total file count protection
                if len(infolist) > cls.MAX_FILES:
                    findings.append(FindingDetail(
                        check_name="archive_analysis",
                        title=f"Archive contains excessive child files ({len(infolist)})",
                        severity="HIGH",
                        finding_type="excessive_archive_files",
                        technical_evidence=f"Child file count is {len(infolist)} (Limit: {cls.MAX_FILES})",
                        potential_harm="May indicate an archive bomb or resource exhaustion attempt."
                    ))

                total_compressed = sum(info.compress_size for info in infolist) or len(file_bytes)
                total_uncompressed = sum(info.file_size for info in infolist)

                # 2. Total uncompressed size limit
                if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                    findings.append(FindingDetail(
                        check_name="archive_analysis",
                        title="Archive uncompressed size exceeds safe threshold",
                        severity="HIGH",
                        finding_type="excessive_uncompressed_size",
                        technical_evidence=f"Uncompressed size is {total_uncompressed / (1024*1024):.1f}MB (Limit: 200MB)",
                        potential_harm="May exhaust disk storage or memory during extraction."
                    ))

                # 3. Expansion ratio (Zip Bomb Protection)
                if total_compressed > 0:
                    ratio = total_uncompressed / float(total_compressed)
                    if ratio > cls.MAX_EXPANSION_RATIO and total_uncompressed > 10 * 1024 * 1024:
                        findings.append(FindingDetail(
                            check_name="archive_analysis",
                            title=f"Suspiciously high archive expansion ratio ({ratio:.1f}x)",
                            severity="CRITICAL",
                            finding_type="zip_bomb_detected",
                            technical_evidence=f"Expansion ratio {ratio:.1f}x exceeds safe limit of {cls.MAX_EXPANSION_RATIO}x",
                            potential_harm="Classic Zip Bomb pattern designed to crash parsers or exhaust system resources."
                        ))

                # 4. Check for nested executable/script children
                for info in infolist:
                    _, ext = os.path.splitext(info.filename.lower())
                    if ext in cls.DANGEROUS_EXTENSIONS:
                        findings.append(FindingDetail(
                            check_name="archive_analysis",
                            title=f"Executable child file detected in archive: '{info.filename}'",
                            severity="HIGH",
                            finding_type="executable_child_file",
                            technical_evidence=f"Archive contains child file '{info.filename}' with executable extension '{ext}'",
                            potential_harm="Could potentially execute code if extracted and launched by user."
                        ))

        except zipfile.BadZipFile:
            findings.append(FindingDetail(
                check_name="archive_analysis",
                title="Malformed or corrupted archive container",
                severity="MODERATE",
                finding_type="malformed_archive",
                technical_evidence="Archive bytes failed standard ZIP parser validation",
                potential_harm="File may be corrupted or malformed."
            ))
        except Exception as e:
            findings.append(FindingDetail(
                check_name="archive_analysis",
                title="Archive analysis error",
                severity="LOW",
                finding_type="archive_analysis_error",
                technical_evidence=str(e),
                potential_harm="Unable to inspect archive contents."
            ))

        return findings
