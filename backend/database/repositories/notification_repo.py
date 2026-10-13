from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.models.notification import Notification

class NotificationRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self,
               user_id: int,
               event_type: str,
               title: str,
               message: str,
               document_id: Optional[int] = None) -> Notification:
        n = Notification(
            user_id=user_id,
            document_id=document_id,
            event_type=event_type,
            title=title,
            message=message
        )
        self.db.add(n)
        self.db.commit()
        self.db.refresh(n)
        return n

    def list_for_user(self, user_id: int, unread_only: bool = False, limit: int = 50) -> List[Notification]:
        query = self.db.query(Notification).filter(Notification.user_id == user_id)
        if unread_only:
            query = query.filter(Notification.is_read == 0)
        return query.order_by(desc(Notification.created_at)).limit(limit).all()

    def mark_read(self, notification_id: int, user_id: int) -> bool:
        n = self.db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.user_id == user_id
        ).first()
        if n:
            n.is_read = 1
            self.db.commit()
            return True
        return False

    def mark_all_read(self, user_id: int):
        self.db.query(Notification).filter(
            Notification.user_id == user_id,
            Notification.is_read == 0
        ).update({"is_read": 1})
        self.db.commit()
