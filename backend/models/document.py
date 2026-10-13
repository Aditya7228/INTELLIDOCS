import os
from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from backend.database.connection import Base

class DocumentModel(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uuid = Column(String, unique=True, nullable=False, index=True)
    original_name = Column(String, nullable=False)
    stored_name = Column(String, unique=True, nullable=False)
    file_path = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    mime_type = Column(String, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String, nullable=False, index=True)
    page_count = Column(Integer, nullable=True)
    word_count = Column(Integer, nullable=True)
    extracted_text = Column(String, nullable=True)
    summary = Column(String, nullable=True)
    key_topics = Column(String, nullable=True)
    language = Column(String, nullable=True)
    category = Column(String, nullable=True, index=True)
    category_source = Column(String, nullable=True)
    sensitivity = Column(String, nullable=False, default="public", index=True)
    has_ocr = Column(Integer, nullable=False, default=0)
    ocr_confidence = Column(Float, nullable=True)
    embedding_stored = Column(Integer, nullable=False, default=0)
    processing_status = Column(String, nullable=False, default="pending", index=True)
    processing_error = Column(String, nullable=True)
    has_embedded_js = Column(Integer, nullable=False, default=0)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    uploaded_at = Column(String, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    processed_at = Column(String, nullable=True)
    is_deleted = Column(Integer, nullable=False, default=0)
    deleted_at = Column(String, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    folder_id = Column(Integer, ForeignKey("folders.id", ondelete="SET NULL"), nullable=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id", ondelete="SET NULL"), nullable=True, index=True)
    subcategory = Column(String, nullable=True)
    version_group_id = Column(String, nullable=True, index=True)
    version_number = Column(Integer, nullable=False, default=1)
    parent_version_id = Column(Integer, ForeignKey("documents.id"), nullable=True)
    perceptual_hash = Column(String, nullable=True, index=True)
    display_name = Column(String, nullable=True)  # Logical user-visible name
    access_lock_hash = Column(String, nullable=True)  # Argon2 password hash for access lock key
    is_access_locked = Column(Integer, nullable=False, default=0, index=True)  # 1 if lock enabled

    tags = relationship("Tag", secondary="document_tags", back_populates="documents")


# Keep clean OOP domain class for non-ORM in-memory representation as specified in OOP architecture
class Document:
    def __init__(
        self,
        name: str,
        path: str,
        filetype: str,
        size: int,
        uuid: str = None,
        sha256_hash: str = None,
        extracted_text: str = None,
        category: str = None,
        sensitivity: str = "public",
        owner_id: int = None
    ):
        self.name = name
        self.path = path
        self.filetype = filetype
        self.size = size
        self.uuid = uuid
        self.sha256_hash = sha256_hash
        self.extracted_text = extracted_text
        self.category = category
        self.sensitivity = sensitivity
        self.owner_id = owner_id

    def is_processable(self) -> bool:
        return bool(self.path and os.path.exists(self.path))

    def word_count(self) -> int:
        return len(self.extracted_text.split()) if self.extracted_text else 0
