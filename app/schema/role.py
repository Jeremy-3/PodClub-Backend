from pydantic import BaseModel,field_validator
from typing import Optional,Union
from uuid import UUID

from app.models.roles import RoleScope

class RoleBase(BaseModel):
    name: str
    active: bool = True

class RoleCreate(RoleBase):
    scope: RoleScope

    model_config = {"extra": "forbid"}

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None

    model_config = {"extra": "forbid"}

class RoleOut(BaseModel):
    id:int
    name:str
    active:bool
    scope: RoleScope
    is_system: bool
    uid:Union[str, UUID]

    @field_validator("name", mode="before")
    def lowercase_role(cls, v: str) -> str:
        return v.lower()



    model_config = {"from_attributes": True}
