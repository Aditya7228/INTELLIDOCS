import json
from pydantic import BaseModel, ConfigDict, field_validator
from typing import Optional, List, Dict, Any

class TagSimple(BaseModel):
    id: int
    name: str
    color: str

    model_config = ConfigDict(from_attributes=True)

class DocumentOut(BaseModel):
    id: int
    uuid: str
    original_name: str
    display_name: Optional[str] = None
    file_type: str
    mime_type: str
    size_bytes: int
    sha256_hash: str
    page_count: Optional[int] = None
    word_count: Optional[int] = None
    extracted_text: Optional[str] = None
    summary: Optional[str] = None
    key_topics: List[str] = []

    @field_validator('key_topics', mode='before')
    @classmethod
    def normalize_key_topics(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return []
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                return []
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item is not None]
            return [str(parsed)]
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        if isinstance(value, (tuple, set)):
            return [str(item) for item in value if item is not None]
        return []
    language: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    folder_id: Optional[int] = None
    sensitivity: str
    has_ocr: int
    ocr_confidence: Optional[float] = None
    version_group_id: Optional[str] = None
    version_number: int = 1
    parent_version_id: Optional[int] = None
    processing_status: str
    owner_id: int
    uploaded_at: str
    is_access_locked: int = 0
    user_permission: Optional[str] = None
    tags: List[TagSimple] = []

    model_config = ConfigDict(from_attributes=True)

class DocumentUpdate(BaseModel):
    display_name: Optional[str] = None
    category: Optional[str] = None
    subcategory: Optional[str] = None
    folder_id: Optional[int] = None
    sensitivity: Optional[str] = None

class DuplicateCandidateOut(BaseModel):
    document_uuid: str
    original_name: str
    relation_type: str
    confidence: float
    scores: Dict[str, float] = {}
    detection_methods: List[str] = []
    supporting_evidence: List[str] = []

DuplicateItem = DuplicateCandidateOut

class DuplicateResultOut(BaseModel):
    document_uuid: str
    has_duplicates: bool
    candidate_count: int
    candidates: List[DuplicateCandidateOut]

class DuplicateDecisionRequest(BaseModel):
    new_doc_uuid: str
    existing_doc_uuid: str
    action: str  # keep_both, trash_new, review

class VersionItemOut(BaseModel):
    id: int
    uuid: str
    original_name: str
    display_name: Optional[str] = None
    version_number: int
    uploaded_at: str
    size_bytes: int

class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[int] = None

class FolderOut(BaseModel):
    id: int
    name: str
    parent_id: Optional[int] = None
    owner_id: int
    created_at: str

    model_config = ConfigDict(from_attributes=True)

class CategoryOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    is_system: int
    owner_id: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class CategoryCreate(BaseModel):
    name: str
    description: Optional[str] = None

class SuggestionOut(BaseModel):
    id: int
    document_id: int
    suggestion_type: str
    current_value: Optional[str] = None
    suggested_value: str
    reason: str
    confidence: float
    status: str
    created_at: str
    evidence: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

class SuggestionEditRequest(BaseModel):
    custom_value: str

class BulkSuggestionRequest(BaseModel):
    suggestion_ids: List[int]

class BulkAnalysisPlanOut(BaseModel):
    analyzed_count: int
    category_counts: Dict[str, int]
    suggestions: List[SuggestionOut]


class NotificationOut(BaseModel):
    id: int
    event_type: str
    title: str
    message: str
    document_id: Optional[int] = None
    document_uuid: Optional[str] = None
    is_read: int
    created_at: str

    model_config = ConfigDict(from_attributes=True)

