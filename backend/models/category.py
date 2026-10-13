from sqlalchemy import Column, Integer, String, ForeignKey
from datetime import datetime, timezone
from backend.database.connection import Base

SYSTEM_CATEGORIES = [
    "Academic", "Certificate", "Assignment", "Resume/CV", "Identity",
    "Financial", "Legal", "Professional", "Personal", "Project", "General"
]

class CategoryModel(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    is_system = Column(Integer, nullable=False, default=0)  # 1=system, 0=user
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)  # NULL for system categories
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
