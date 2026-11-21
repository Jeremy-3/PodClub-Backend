from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class PodClubBase(BaseModel):
    name: str
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: bool = True
    is_private: bool = False
    owner_id: Optional[int] = None


class PodClubCreate(PodClubBase):
    pass


class PodClubUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: Optional[bool] = None
    is_private: Optional[bool] = None
    owner_id: Optional[int] = None


class PodClubOut(PodClubBase):
    id: int
    uid: UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
