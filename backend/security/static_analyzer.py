import re
import os
import zipfile
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from backend.security.file_validator import FileValidator

@dataclass
class FindingDetail:
    check_name: str
    title: str
    severity: str  # NEUTRAL, LOW, MODERATE, HIGH, CRITICAL
    finding_type: str
    technical_evidence: str
    potential_harm: str
    confidence: str = "HIGH"

class StaticSecurityAnalyzer:
    """
    Performs identity validation and static structural analysis on PDFs, DOCX, and images.
    """

    SUSPICIOUS_PDF_OBJECTS = {
        r"/JavaScript": ("Embedded JavaScript detected", "MODERATE", "PDF contains embedded JavaScript code which could execute actions when opened."),
        r"/JS\b": ("Embedded JS action detected", "MODERATE", "PDF contains embedded JS action specifier."),
        r"/Launch": ("Embedded launch action detected", "HIGH", "Launch actions can be abused to trigger external applications or system commands."),
        r"/EmbeddedFiles": ("Embedded payload/attachment detected", "MODERATE", "Document contains embedded file attachments which could be executables or scripts."),
        r"/OpenAction": ("Automatic open action detected", "LOW", "Document executes an automated action immediately upon opening."),
        r"/AA\b": ("Additional actions (AA) trigger detected", "LOW", "Document contains event-triggered automatic actions."),
        r"/URI": ("External URL link reference detected", "NEUTRAL", "Document contains external web links. Links may lead to external resources.")
    }

    SUSPICIOUS_ZIP_EXTENSIONS = {
        ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".jar", ".js", ".py", ".sh", ".cpl", ".hta", ".pif"
    }

    @classmethod
    def analyze_identity(cls, filename: str, declared_mime: str, file_bytes: bytes) -> List[FindingDetail]:
        findings = []

        # 1. Null byte injection in filename
        if "\x00" in filename:
            findings.append(FindingDetail(
                check_name="file_identity",
                title="Null byte in filename",
                severity="CRITICAL",
                finding_type="null_byte_injection",
                technical_evidence=f"Filename '{filename}' contains null byte (0x00)",
                potential_harm="May be used for path traversal or extension spoofing."
            ))

        # 2. Extension check
        _, ext = os.path.splitext(filename.lower())
        if not ext:
            findings.append(FindingDetail(
                check_name="file_identity",
                title="Missing file extension",
                severity="LOW",
                finding_type="missing_extension",
                technical_evidence=f"Filename '{filename}' has no extension",
                potential_harm="May cause MIME type misinterpretation."
            ))

        # 3. Magic bytes detection vs declared MIME
        detected_mime = FileValidator.detect_mime_type(file_bytes, declared_mime)
        if detected_mime == "application/octet-stream":
            findings.append(FindingDetail(
                check_name="file_identity",
                title="Unrecognized magic bytes",
                severity="MODERATE",
                finding_type="mime_unrecognized",
                technical_evidence=f"Header bytes do not match standard document signatures for '{filename}'",
                potential_harm="File structure may be malformed or obfuscated."
            ))
        elif declared_mime and declared_mime.lower() != detected_mime.lower():
            # Flag mismatch as low/moderate evidence, not automatic malware
            findings.append(FindingDetail(
                check_name="file_identity",
                title="MIME type mismatch",
                severity="LOW",
                finding_type="mime_mismatch",
                technical_evidence=f"Declared MIME '{declared_mime}' differs from magic-byte detected MIME '{detected_mime}'",
                potential_harm="Declared container type does not match true file contents."
            ))

        return findings

    @classmethod
    def analyze_structure(cls, file_path: str, mime_type: str, file_bytes: bytes) -> List[FindingDetail]:
        findings = []
        
        if mime_type == "application/pdf":
            findings.extend(cls._analyze_pdf_structure(file_bytes))
        elif mime_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
            findings.extend(cls._analyze_docx_structure(file_path, file_bytes))
        elif mime_type.startswith("image/"):
            findings.extend(cls._analyze_image_structure(file_bytes))

        return findings

    @classmethod
    def _analyze_pdf_structure(cls, file_bytes: bytes) -> List[FindingDetail]:
        findings = []
        try:
            content_str = file_bytes.decode("latin-1", errors="ignore")
        except Exception:
            return findings

        # Check for PDF header integrity
        if not file_bytes.startswith(b"%PDF-"):
            findings.append(FindingDetail(
                check_name="file_structure",
                title="Malformed PDF header",
                severity="MODERATE",
                finding_type="malformed_pdf_header",
                technical_evidence="File does not start with standard '%PDF-' magic bytes",
                potential_harm="May indicate corrupted structure or exploit attempt."
            ))

        # Check for suspicious PDF stream objects
        for pattern, (title, severity, harm) in cls.SUSPICIOUS_PDF_OBJECTS.items():
            matches = re.findall(pattern, content_str)
            if matches:
                findings.append(FindingDetail(
                    check_name="file_structure",
                    title=title,
                    severity=severity,
                    finding_type="suspicious_pdf_object",
                    technical_evidence=f"Found {len(matches)} instance(s) matching object pattern '{pattern}'",
                    potential_harm=harm
                ))

        # Count external links specifically to extract count for evidence
        url_matches = re.findall(r"https?://[^\s<>\"']+", content_str)
        if url_matches and not any(f.finding_type == "external_url_detected" for f in findings):
            findings.append(FindingDetail(
                check_name="file_structure",
                title="External resource references detected",
                severity="NEUTRAL",
                finding_type="external_url_detected",
                technical_evidence=f"Detected {len(url_matches)} external URL reference(s) inside document",
                potential_harm="External links could potentially lead to phishing or external resources. Presence of URLs alone does not indicate malware."
            ))

        return findings

    @classmethod
    def _analyze_docx_structure(cls, file_path: str, file_bytes: bytes) -> List[FindingDetail]:
        findings = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                namelist = zf.namelist()
                normalized_names = {name.replace("\\", "/").lower() for name in namelist}

                # Minimum OOXML structure required for a normal DOCX document.
                required_entries = {"[content_types].xml", "word/document.xml"}
                missing_entries = sorted(required_entries - normalized_names)
                if missing_entries:
                    findings.append(FindingDetail(
                        check_name="file_structure",
                        title="Invalid DOCX OOXML structure",
                        severity="MODERATE",
                        finding_type="invalid_ooxml_structure",
                        technical_evidence=(
                            "DOCX ZIP container is missing required OOXML entries: "
                            + ", ".join(missing_entries)
                        ),
                        potential_harm="Malformed Office containers may fail to open correctly or conceal unusual payloads."
                    ))

                # Normalize case correctly before looking for the VBA macro stream.
                if any("vbaproject.bin" in name for name in normalized_names):
                    findings.append(FindingDetail(
                        check_name="file_structure",
                        title="VBA macro payload container detected",
                        severity="MODERATE",
                        finding_type="vba_macro_detected",
                        technical_evidence="Archive contains 'vbaProject.bin' macro stream",
                        potential_harm="Macros can execute automated code when enabled in Microsoft Word."
                    ))

                # Check for executable/script entries inside the Office container.
                for name in namelist:
                    _, ext = os.path.splitext(name.lower())
                    if ext in cls.SUSPICIOUS_ZIP_EXTENSIONS:
                        findings.append(FindingDetail(
                            check_name="file_structure",
                            title=f"Suspicious embedded entry '{name}' inside Office container",
                            severity="HIGH",
                            finding_type="embedded_executable_child",
                            technical_evidence=f"DOCX container includes child entry '{name}' with extension '{ext}'",
                            potential_harm="Could contain an executable payload packaged inside document XML container."
                        ))

        except zipfile.BadZipFile:
            findings.append(FindingDetail(
                check_name="file_structure",
                title="Malformed DOCX archive container",
                severity="MODERATE",
                finding_type="malformed_zip",
                technical_evidence="File is declared as DOCX but is not a valid ZIP container",
                potential_harm="File cannot be parsed properly by office software or may be corrupted."
            ))
        except Exception as e:
            findings.append(FindingDetail(
                check_name="file_structure",
                title="DOCX structure parse error",
                severity="LOW",
                finding_type="docx_parse_error",
                technical_evidence=str(e),
                potential_harm="Unable to inspect internal zip entries."
            ))

        return findings

    @classmethod
    def _analyze_image_structure(cls, file_bytes: bytes) -> List[FindingDetail]:
        findings = []

        # Verify that the claimed image bytes are actually decodable.
        try:
            import io
            from PIL import Image
            with Image.open(io.BytesIO(file_bytes)) as image:
                image.verify()
        except Exception as e:
            findings.append(FindingDetail(
                check_name="file_structure",
                title="Invalid image structure",
                severity="MODERATE",
                finding_type="invalid_image_structure",
                technical_evidence=f"Pillow image verification failed: {e}",
                potential_harm="Malformed image data may fail during rendering or trigger unsafe parser behavior."
            ))

        if len(file_bytes) > 10 * 1024 * 1024:
            findings.append(FindingDetail(
                check_name="file_structure",
                title="Unusually large image size",
                severity="LOW",
                finding_type="large_image",
                technical_evidence=f"Image size is {len(file_bytes)} bytes (> 10MB)",
                potential_harm="May consume high memory during rendering."
            ))

        return findings
