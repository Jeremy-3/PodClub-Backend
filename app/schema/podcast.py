from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class PodcastBase(BaseModel):
    podclub_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: bool = True


class PodcastCreate(PodcastBase):
    model_config = {"extra": "forbid"}


class PodcastCreateDB(PodcastCreate):
    creator_id: int


class PodcastUpdate(BaseModel):
    podclub_id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: Optional[bool] = None

    model_config = {"extra": "forbid"}


class PodcastOut(PodcastBase):
    id: int
    uid: UUID
    creator_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
