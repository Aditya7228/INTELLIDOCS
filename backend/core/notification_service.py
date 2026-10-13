from typing import Optional
from sqlalchemy.orm import Session
from backend.database.repositories.notification_repo import NotificationRepository

class NotificationService:
    """Creates safe local notifications. Never includes secrets, tokens, or raw PII."""

    @staticmethod
    def notify(
        db: Session,
        user_id: int,
        event_type: str,
        title: str,
        message: str,
        document_id: Optional[int] = None
    ):
        try:
            repo = NotificationRepository(db)
            repo.create(
                user_id=user_id,
                event_type=event_type,
                title=title,
                message=message,
                document_id=document_id
            )
        except Exception:
            pass  # Notifications must never crash primary workflow
