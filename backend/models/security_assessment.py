import os
import json
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.database.connection import Base

class SecurityAssessmentModel(Base):
    __tablename__ = "security_assessments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    quarantine_uuid = Column(String, unique=True, nullable=False, index=True)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    original_name = Column(String, nullable=False)
    stored_quarantine_name = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    mime_type = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String, nullable=False, index=True)
    
    risk_score = Column(Integer, nullable=False, default=0)  # 0 to 100
    risk_level = Column(String, nullable=False, default="LOW RISK", index=True)  # LOW RISK, SUSPICIOUS, HIGH RISK, MALICIOUS
    confidence = Column(String, nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH
    verdict = Column(String, nullable=False, default="SAFE", index=True)  # SAFE, SUSPICIOUS, BLOCKED
    
    data_sensitivity = Column(String, nullable=False, default="public")  # public, internal, confidential, restricted
    pii_detected = Column(Integer, nullable=False, default=0)  # 0 or 1
    scanner_status = Column(String, nullable=False, default="AVAILABLE")  # AVAILABLE, UNAVAILABLE, PARTIAL
    
    check_states_json = Column(Text, nullable=False, default="{}")  # JSON: {check_name: state}
    findings_json = Column(Text, nullable=False, default="[]")  # JSON: list of findings
    why_explanations_json = Column(Text, nullable=False, default="[]")  # JSON: list of explanations
    potential_harms_json = Column(Text, nullable=False, default="[]")  # JSON: list of potential harms
    recommended_action = Column(Text, nullable=True)
    
    quarantine_status = Column(String, nullable=False, default="QUARANTINED", index=True)  # QUARANTINED, PROMOTED, BLOCKED, DELETED
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    rescan_count = Column(Integer, nullable=False, default=0)

    findings = relationship("SecurityFindingModel", back_populates="assessment", cascade="all, delete-orphan")


class SecurityFindingModel(Base):
    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("security_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    
    check_name = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="LOW")  # NEUTRAL, LOW, MODERATE, HIGH, CRITICAL
    finding_type = Column(String, nullable=False)
    technical_evidence = Column(Text, nullable=True)
    potential_harm = Column(Text, nullable=True)
    confidence = Column(String, nullable=False, default="HIGH")
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    assessment = relationship("SecurityAssessmentModel", back_populates="findings")
