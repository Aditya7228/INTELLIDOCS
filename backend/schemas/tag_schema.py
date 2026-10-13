from pydantic import BaseModel, ConfigDict
from typing import List, Optional

class TagCreate(BaseModel):
    name: str
    color: Optional[str] = "#6366f1"

class TagUpdate(BaseModel):
    name: Optional[str] = None
    color: Optional[str] = None

class TagOut(BaseModel):
    id: int
    name: str
    color: str
    document_count: Optional[int] = 0
    created_by: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class TagAssign(BaseModel):
    tag_ids: List[int]
