from sqlalchemy import Column, Integer, ForeignKey
from backend.database.connection import Base

class UserNotificationSettings(Base):
    __tablename__ = "user_notification_settings"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True)
    email_notifications = Column(Integer, nullable=False, default=1)
    in_app_notifications = Column(Integer, nullable=False, default=1)
    suggestion_alerts = Column(Integer, nullable=False, default=1)
    duplicate_alerts = Column(Integer, nullable=False, default=1)
    security_alerts = Column(Integer, nullable=False, default=1)
