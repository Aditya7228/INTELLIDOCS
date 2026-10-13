from typing import Optional
from sqlalchemy.orm import Session
from backend.database.repositories.audit_repo import AuditRepository

class AuditService:
    @staticmethod
    def log(
        db: Session,
        action: str,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        detail: Optional[dict] = None,
        success: int = 1
    ):
        try:
            repo = AuditRepository(db)
            repo.log_event(
                action=action,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                user_agent=user_agent,
                detail=detail,
                success=success
            )
        except Exception:
            pass  # Audit logging should never crash primary workflow
