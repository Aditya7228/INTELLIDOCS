from pydantic import BaseModel
from typing import List, Optional
from backend.schemas.document_schema import DocumentOut

class SearchHit(BaseModel):
    document: DocumentOut
    score: float
    snippet: Optional[str] = None

class SearchResultOut(BaseModel):
    query: str
    total: int
    page: int
    results: List[SearchHit]

class AutocompleteOut(BaseModel):
    prefix: str
    suggestions: List[str]
