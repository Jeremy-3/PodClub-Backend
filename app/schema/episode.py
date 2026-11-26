from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class EpisodeBase(BaseModel):
    podcast_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    audio_url: str
    duration: int
    is_active: bool = True


class EpisodeCreate(EpisodeBase):
    published_at: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class EpisodeUpdate(BaseModel):
    podcast_id: Optional[int] = None
    title: Optional[str] = None
    description: Optional[str] = None
    audio_url: Optional[str] = None
    duration: Optional[int] = None
    published_at: Optional[datetime] = None
    is_active: Optional[bool] = None

    model_config = {"extra": "forbid"}


class EpisodeOut(EpisodeBase):
    id: int
    uid: UUID
    play_count: int
    published_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
