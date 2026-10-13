from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class SecurityFindingOut(BaseModel):
    check_name: str
    title: str
    severity: str
    finding_type: str
    technical_evidence: Optional[str] = None
    potential_harm: Optional[str] = None
    confidence: str

    class Config:
        from_attributes = True

class SecurityAssessmentOut(BaseModel):
    id: int
    quarantine_uuid: str
    document_id: Optional[int] = None
    original_name: str
    file_type: str
    mime_type: str
    size_bytes: int
    sha256_hash: str
    risk_score: int
    risk_level: str
    confidence: str
    verdict: str
    data_sensitivity: str
    pii_detected: bool
    scanner_status: str
    check_states: Dict[str, str]
    findings: List[SecurityFindingOut]
    why_explanations: List[str]
    potential_harms: List[str]
    recommended_action: str
    quarantine_status: str
    created_at: str
    rescan_count: int

    class Config:
        from_attributes = True

class PromoteRequest(BaseModel):
    reason: Optional[str] = None
