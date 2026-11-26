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


class PodClubCreate(PodClubBase):
    model_config = {"extra": "forbid"}


class PodClubCreateDB(PodClubCreate):
    owner_id: int


class PodClubUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: Optional[bool] = None
    is_private: Optional[bool] = None

    model_config = {"extra": "forbid"}


class PodClubOut(PodClubBase):
    id: int
    uid: UUID
    owner_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
