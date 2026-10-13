from typing import List, Optional
from sqlalchemy.orm import Session
from backend.models.security_assessment import SecurityAssessmentModel, SecurityFindingModel

class SecurityRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_quarantine_uuid(self, quarantine_uuid: str) -> Optional[SecurityAssessmentModel]:
        return self.db.query(SecurityAssessmentModel).filter(
            SecurityAssessmentModel.quarantine_uuid == quarantine_uuid
        ).first()

    def get_by_document_id(self, document_id: int) -> Optional[SecurityAssessmentModel]:
        return self.db.query(SecurityAssessmentModel).filter(
            SecurityAssessmentModel.document_id == document_id
        ).first()

    def list_quarantined_for_user(self, owner_id: int) -> List[SecurityAssessmentModel]:
        return self.db.query(SecurityAssessmentModel).filter(
            SecurityAssessmentModel.owner_id == owner_id,
            SecurityAssessmentModel.quarantine_status.in_(["QUARANTINED", "BLOCKED"])
        ).order_by(SecurityAssessmentModel.created_at.desc()).all()

    def update_status(self, assessment_id: int, quarantine_status: str, document_id: Optional[int] = None):
        assessment = self.db.query(SecurityAssessmentModel).filter(SecurityAssessmentModel.id == assessment_id).first()
        if assessment:
            assessment.quarantine_status = quarantine_status
            if document_id is not None:
                assessment.document_id = document_id
            self.db.commit()
            self.db.refresh(assessment)
        return assessment
