from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class PodcastBase(BaseModel):
    podclub_id: Optional[int] = None
    creator_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: bool = True


class PodcastCreate(PodcastBase):
    pass


class PodcastUpdate(BaseModel):
    podclub_id: Optional[int] = None
    creator_id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: Optional[bool] = None


class PodcastOut(PodcastBase):
    id: int
    uid: UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
