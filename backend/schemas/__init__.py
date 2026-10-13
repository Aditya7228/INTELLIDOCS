from backend.schemas.auth_schema import UserRegister, UserLogin, TokenResponse, UserOut, RefreshTokenRequest, ChangePassword
from backend.schemas.document_schema import (
    DocumentOut, DocumentUpdate, DuplicateCandidateOut, DuplicateResultOut, TagSimple,
    FolderOut, FolderCreate, CategoryOut, CategoryCreate, SuggestionOut, NotificationOut
)
from backend.schemas.tag_schema import TagCreate, TagOut, TagAssign
from backend.schemas.search_schema import SearchHit, SearchResultOut, AutocompleteOut
from backend.schemas.audit_schema import AuditLogOut

DuplicateItem = DuplicateCandidateOut

__all__ = [
    "UserRegister", "UserLogin", "TokenResponse", "UserOut", "RefreshTokenRequest", "ChangePassword",
    "DocumentOut", "DocumentUpdate", "DuplicateItem", "DuplicateCandidateOut", "DuplicateResultOut", "TagSimple",
    "FolderOut", "FolderCreate", "CategoryOut", "CategoryCreate", "SuggestionOut", "NotificationOut",
    "TagCreate", "TagOut", "TagAssign",
    "SearchHit", "SearchResultOut", "AutocompleteOut",
    "AuditLogOut"
]
