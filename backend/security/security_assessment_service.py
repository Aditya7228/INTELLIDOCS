import json
import os
import re
from typing import Tuple, Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.models.security_assessment import SecurityAssessmentModel, SecurityFindingModel
from backend.security.quarantine_manager import QuarantineManager
from backend.security.static_analyzer import StaticSecurityAnalyzer, FindingDetail
from backend.security.malware_scanner import MalwareScannerAdapter, ScanResult
from backend.security.archive_analyzer import ArchiveAnalyzer
from backend.security.unified_risk_engine import UnifiedRiskEngine, RiskEvaluation
from backend.security.file_validator import FileValidator
from backend.algorithms.hashing import sha256_bytes
from backend.core.audit_service import AuditService
from backend.core.sensitivity_service import SensitivityService
from backend.document_processing.base_processor import DocumentProcessor

class SecurityAssessmentService:
    """
    Orchestrates the File Security Intelligence pipeline as the First Security Gate in the upload lifecycle.
    """

    def __init__(self):
        self.quarantine_manager = QuarantineManager()
        self.sensitivity_service = SensitivityService()

    def run_assessment(
        self,
        db: Session,
        filename: str,
        content_type: str,
        file_bytes: bytes,
        owner_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> SecurityAssessmentModel:
        # 1. Store in untrusted temporary quarantine
        q_uuid, q_stored_name, q_path = self.quarantine_manager.save_to_quarantine(file_bytes, filename)
        sha256_hash = sha256_bytes(file_bytes)

        # Basic mime validation
        val_res = FileValidator.validate_upload(filename, content_type, file_bytes)
        file_type = val_res.file_type or "unknown"
        mime_type = val_res.mime_type or content_type or "application/octet-stream"

        # Initialize check states map
        check_states = {
            "file_identity": "RUNNING",
            "file_structure": "PENDING",
            "malware_scan": "PENDING",
            "embedded_content": "PENDING",
            "content_evidence": "PENDING"
        }

        all_findings: List[FindingDetail] = []

        # A failed basic validator result is a security-gate failure. Keep the
        # object quarantined and expose the reason to the risk engine/report.
        if not val_res.valid:
            all_findings.append(FindingDetail(
                check_name="file_validation",
                title="Upload validation failed",
                severity="HIGH",
                finding_type="upload_validation_failed",
                technical_evidence=val_res.error or "File failed upload validation.",
                potential_harm="The uploaded object is not eligible for normal IntelliDocs processing.",
                confidence="HIGH"
            ))

        # Step 1: File Identity Check
        identity_findings = StaticSecurityAnalyzer.analyze_identity(filename, mime_type, file_bytes)
        all_findings.extend(identity_findings)
        if any(f.severity in ["HIGH", "CRITICAL"] for f in identity_findings):
            check_states["file_identity"] = "FAILED"
        elif identity_findings:
            check_states["file_identity"] = "WARNING"
        else:
            check_states["file_identity"] = "PASSED"

        if not val_res.valid:
            check_states["file_identity"] = "FAILED"

        # Step 2: Structure Analysis Check
        check_states["file_structure"] = "RUNNING"
        structure_findings = StaticSecurityAnalyzer.analyze_structure(str(q_path), mime_type, file_bytes)
        all_findings.extend(structure_findings)
        if any(f.severity in ["HIGH", "CRITICAL"] for f in structure_findings):
            check_states["file_structure"] = "FAILED"
        elif structure_findings:
            check_states["file_structure"] = "WARNING"
        else:
            check_states["file_structure"] = "PASSED"

        # Step 3: Malware Scan Check
        check_states["malware_scan"] = "RUNNING"
        scan_res: ScanResult = MalwareScannerAdapter.scan_file(str(q_path), file_bytes)
        all_findings.extend(scan_res.findings)
        if scan_res.status == "BLOCKED":
            check_states["malware_scan"] = "BLOCKED"
        elif not scan_res.available:
            check_states["malware_scan"] = "UNAVAILABLE"
        elif scan_res.status == "PASSED":
            check_states["malware_scan"] = "PASSED"
        else:
            check_states["malware_scan"] = "WARNING"

        # Keep a safe, user-facing diagnostic in the report when no scan result exists.
        # This is static diagnostic text from the scanner adapter, not AI-generated output.
        if not scan_res.available and scan_res.detail_message:
            check_states["malware_scan_detail"] = scan_res.detail_message

        # Step 4: Archive & Embedded Content Analysis
        check_states["embedded_content"] = "RUNNING"
        archive_findings = ArchiveAnalyzer.analyze_archive(str(q_path), mime_type, file_bytes)
        all_findings.extend(archive_findings)
        if any(f.severity in ["HIGH", "CRITICAL"] for f in archive_findings):
            check_states["embedded_content"] = "FAILED"
        elif archive_findings:
            check_states["embedded_content"] = "WARNING"
        else:
            check_states["embedded_content"] = "PASSED"

        # Step 5: Safe Text & PII Content Evidence Gathering
        check_states["content_evidence"] = "RUNNING"
        ocr_text = ""
        pii_types = []

        if not val_res.valid:
            check_states["content_evidence"] = "SKIPPED"
        else:
            try:
                processor = DocumentProcessor.for_mime_type(mime_type)
                proc_res = processor.extract(q_path)
                ocr_text = proc_res.text or ""

                if not ocr_text:
                    raw_sample = file_bytes[:2 * 1024 * 1024]
                    printable_chunks = re.findall(rb"[ -~]{4,}", raw_sample)
                    if printable_chunks:
                        ocr_text = "\n".join(
                            chunk.decode("latin-1", errors="ignore")
                            for chunk in printable_chunks
                        )

                if ocr_text:
                    _, pii_types = self.sensitivity_service.analyze(ocr_text)

                extraction_warning = bool(
                    getattr(proc_res, "metadata", {}).get("extraction_warning")
                )
                check_states["content_evidence"] = (
                    "WARNING" if extraction_warning and not proc_res.text else "PASSED"
                )
            except Exception:
                check_states["content_evidence"] = "WARNING"

        # Step 6: Unified Risk Evaluation
        eval_res: RiskEvaluation = UnifiedRiskEngine.evaluate(
            findings=all_findings,
            scanner_available=scan_res.available,
            scanner_status=scan_res.status,
            pii_types=pii_types,
            ocr_text=ocr_text
        )

        # Construct DB Model Record
        assessment = SecurityAssessmentModel(
            quarantine_uuid=q_uuid,
            owner_id=owner_id,
            original_name=filename,
            stored_quarantine_name=q_stored_name,
            file_type=file_type,
            mime_type=mime_type,
            size_bytes=len(file_bytes),
            sha256_hash=sha256_hash,
            risk_score=eval_res.risk_score,
            risk_level=eval_res.risk_level,
            confidence=eval_res.confidence,
            verdict=eval_res.verdict,
            data_sensitivity=eval_res.data_sensitivity,
            pii_detected=1 if eval_res.pii_detected else 0,
            scanner_status=eval_res.scanner_status,
            check_states_json=json.dumps(check_states),
            findings_json=json.dumps([{
                "check_name": f.check_name,
                "title": f.title,
                "severity": f.severity,
                "finding_type": f.finding_type,
                "technical_evidence": f.technical_evidence,
                "potential_harm": f.potential_harm,
                "confidence": f.confidence
            } for f in all_findings]),
            why_explanations_json=json.dumps(eval_res.why_explanations),
            potential_harms_json=json.dumps(eval_res.potential_harms),
            recommended_action=eval_res.recommended_action,
            quarantine_status="BLOCKED" if eval_res.verdict == "BLOCKED" else ("QUARANTINED" if eval_res.verdict == "SUSPICIOUS" else "PROMOTED")
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        # Add findings records
        for f in all_findings:
            f_model = SecurityFindingModel(
                assessment_id=assessment.id,
                check_name=f.check_name,
                title=f.title,
                severity=f.severity,
                finding_type=f.finding_type,
                technical_evidence=f.technical_evidence,
                potential_harm=f.potential_harm,
                confidence=f.confidence
            )
            db.add(f_model)
        db.commit()

        # Audit Logging
        AuditService.log(
            db,
            action=f"DOCUMENT_SECURITY_GATE_{eval_res.verdict}",
            user_id=owner_id,
            resource_type="quarantine",
            resource_id=q_uuid,
            ip_address=ip_address,
            user_agent=user_agent,
            detail={
                "original_name": filename,
                "verdict": eval_res.verdict,
                "risk_score": eval_res.risk_score,
                "risk_level": eval_res.risk_level,
                "confidence": eval_res.confidence,
                "scanner_status": eval_res.scanner_status,
                "findings_count": len(all_findings)
            }
        )

        return assessment
