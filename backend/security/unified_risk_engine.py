from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from backend.security.static_analyzer import FindingDetail

@dataclass
class RiskEvaluation:
    risk_score: int
    risk_level: str  # LOW RISK, SUSPICIOUS, HIGH RISK, MALICIOUS
    confidence: str  # LOW, MEDIUM, HIGH
    verdict: str     # SAFE, SUSPICIOUS, BLOCKED
    scanner_status: str  # AVAILABLE, UNAVAILABLE, PARTIAL
    why_explanations: List[str]
    potential_harms: List[str]
    recommended_action: str
    data_sensitivity: str
    pii_detected: bool

class UnifiedRiskEngine:
    """
    Evidence-based unified risk engine for document security intelligence.
    Distinguishes security risk from data sensitivity, PII, and scanner availability.
    Prevents false positives by design.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 50,
        "HIGH": 30,
        "MODERATE": 15,
        "LOW": 5,
        "NEUTRAL": 2
    }

    @classmethod
    def evaluate(
        cls,
        findings: List[FindingDetail],
        scanner_available: bool,
        scanner_status: str,
        pii_types: List[str],
        ocr_text: str
    ) -> RiskEvaluation:
        score = 0
        has_confirmed_malware = False
        has_critical_payload = False

        why_list = []
        harm_list = []

        for f in findings:
            weight = cls.SEVERITY_WEIGHTS.get(f.severity.upper(), 5)
            
            # Special case rules
            if f.finding_type == "confirmed_malware":
                score += 95
                has_confirmed_malware = True
            elif f.finding_type == "zip_bomb_detected":
                score += 75
                has_critical_payload = True
            elif f.finding_type == "null_byte_injection":
                score += 70
                has_critical_payload = True
            elif f.finding_type == "upload_validation_failed":
                # Validation findings are HIGH severity and therefore quarantine the
                # object through the normal SUSPICIOUS risk tier without changing
                # existing legacy verdict semantics for malformed test fixtures.
                score += weight
            elif f.finding_type == "external_url_detected":
                # External URL is neutral - low impact
                score += 5
                why_list.append(f"{f.technical_evidence}")
                harm_list.append(f.potential_harm)
                continue
            else:
                score += weight

            why_list.append(f"{f.title}: {f.technical_evidence}")
            if f.potential_harm and f.potential_harm not in harm_list:
                harm_list.append(f.potential_harm)

        # Cap score at 100
        score = min(100, score)

        # Calculate Data Sensitivity vs Security Risk
        has_pii = bool(pii_types and len(pii_types) > 0)
        data_sensitivity = "public"
        if has_pii:
            if any(p in ["SSN", "AADHAAR", "PAN", "CREDIT_CARD", "BANK_ACCOUNT"] for p in pii_types):
                data_sensitivity = "restricted"
            else:
                data_sensitivity = "confidential"
            why_list.append(f"Document contains sensitive data types: {', '.join(pii_types)}. Note: Data sensitivity is distinct from security malware risk.")

        # Determine Risk Level
        if score >= 90 or has_confirmed_malware:
            risk_level = "MALICIOUS"
        elif score >= 70 or has_critical_payload:
            risk_level = "HIGH RISK"
        elif score >= 30:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "LOW RISK"

        # Determine Verdict
        if has_confirmed_malware or score >= 90:
            verdict = "BLOCKED"
        elif score >= 30 or risk_level in ["SUSPICIOUS", "HIGH RISK"]:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Determine Confidence
        if not scanner_available:
            confidence = "MEDIUM"
            why_list.append("Malware scanner was unavailable or not configured. Assessment relies on static analysis and structure verification.")
        else:
            confidence = "HIGH"

        # If clean and safe
        if score < 30 and not why_list:
            why_list = [
                "Valid document header signature",
                "Declared MIME type matches file structure",
                "No executable payload or macro stream detected",
                "No known malware signature detected"
            ]
            harm_list = ["No significant security harm identified."]

        # Recommended Action
        if verdict == "BLOCKED":
            recommended = "Do not open or execute this file. It has been isolated in quarantine and blocked from normal IntelliDocs processing."
        elif verdict == "SUSPICIOUS":
            recommended = "Review the security findings before using this document. It remains quarantined and will not enter your library until reviewed."
        elif not scanner_available:
            recommended = "Available static and structural checks passed, but the malware scanner is unavailable. Assessment confidence is limited; configure a malware scanner for stronger clearance."
        else:
            recommended = "Document passed available security checks. Normal use and processing is permitted."

        return RiskEvaluation(
            risk_score=score,
            risk_level=risk_level,
            confidence=confidence,
            verdict=verdict,
            scanner_status="AVAILABLE" if scanner_available else "UNAVAILABLE",
            why_explanations=why_list,
            potential_harms=harm_list,
            recommended_action=recommended,
            data_sensitivity=data_sensitivity,
            pii_detected=has_pii
        )
