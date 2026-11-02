from pydantic import BaseModel,field_validator
from typing import Optional,Union
from uuid import UUID

class RoleBase(BaseModel):
    name: str
    active: bool = True

class RoleCreate(RoleBase):
    pass

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    active: Optional[bool] = None

class RoleOut(BaseModel):
    id:int
    name:str
    active:bool
    uid:Union[str, UUID]

    @field_validator("name", mode="before")
    def lowercase_role(cls, v: str) -> str:
        return v.lower()



    model_config = {"from_attributes": True}
