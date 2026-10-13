from sqlalchemy import Column, Integer, String, ForeignKey, UniqueConstraint
from datetime import datetime, timezone
from backend.database.connection import Base

class FolderModel(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False)
    parent_id = Column(Integer, ForeignKey("folders.id", ondelete="CASCADE"), nullable=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    created_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    __table_args__ = (
        UniqueConstraint("name", "parent_id", "owner_id", name="uq_folder_name_parent_owner"),
    )
