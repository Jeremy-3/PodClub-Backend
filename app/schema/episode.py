from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, model_validator

from app.schema.brief import ClubBrief, PodcastBrief, UserBrief


class EpisodeBase(BaseModel):
    podcast_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    audio_url: str
    duration: int
    is_active: bool = True


class EpisodeCreate(EpisodeBase):
    podcast_id: int
    published_at: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class EpisodeCreateDB(EpisodeCreate):
    created_by_id: int


class EpisodeUpdate(BaseModel):
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
    created_by: Optional[UserBrief] = None
    podcast: Optional[PodcastBrief] = None
    podclub: Optional[ClubBrief] = None

    @model_validator(mode="before")
    @classmethod
    def enrich_from_orm(cls, value):
        if isinstance(value, dict):
            return value
        if not hasattr(value, "id"):
            return value
        podcast = value.podcast
        return {
            "podcast_id": value.podcast_id,
            "title": value.title,
            "description": value.description,
            "audio_url": value.audio_url,
            "duration": value.duration,
            "is_active": value.is_active,
            "id": value.id,
            "uid": value.uid,
            "play_count": value.play_count,
            "published_at": value.published_at,
            "created_at": value.created_at,
            "updated_at": value.updated_at,
            "created_by": value.created_by,
            "podcast": podcast,
            "podclub": podcast.podclub if podcast is not None else None,
        }

    model_config = {"from_attributes": True}
