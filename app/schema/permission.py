from pydantic import BaseModel
from typing import Union, Optional
from uuid import UUID

class PermissionBase(BaseModel):
    name: str
    description: str  
    category: str

class PermissionCreate(PermissionBase):
    model_config = {"extra": "forbid"}

class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None

    model_config = {"extra": "forbid"}

class PermissionOut(PermissionBase):
    id: int
    uid: Union[str, UUID]

    model_config = {"from_attributes": True}