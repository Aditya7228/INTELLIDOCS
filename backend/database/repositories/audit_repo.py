import json
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.models.audit_log import AuditLog

class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def log_event(
        self,
        action: str,
        user_id: Optional[int] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        detail: Optional[dict] = None,
        success: int = 1
    ) -> AuditLog:
        detail_str = json.dumps(detail) if detail else None
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            detail=detail_str,
            success=success
        )
        self.db.add(log_entry)
        self.db.commit()
        self.db.refresh(log_entry)
        return log_entry

    def list_logs(
        self,
        page: int = 1,
        limit: int = 50,
        user_id: Optional[int] = None,
        action: Optional[str] = None
    ) -> Tuple[List[AuditLog], int]:
        query = self.db.query(AuditLog)
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)

        total = query.count()
        logs = query.order_by(desc(AuditLog.timestamp)).offset((page - 1) * limit).limit(limit).all()
        return logs, total
