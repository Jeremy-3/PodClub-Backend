from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, model_validator

from app.schema.brief import ClubBrief, UserBrief


class PodcastBase(BaseModel):
    podclub_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    cover_url: Optional[str] = None
    is_active: bool = True


class PodcastCreate(PodcastBase):
    podclub_id: int

    model_config = {"extra": "forbid"}


class PodcastCreateDB(PodcastCreate):
    creator_id: int


class PodcastUpdate(BaseModel):
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
    creator: Optional[UserBrief] = None
    episode_count: int = 0
    podclub: Optional[ClubBrief] = None

    @model_validator(mode="before")
    @classmethod
    def enrich_from_orm(cls, value):
        if isinstance(value, dict):
            return value
        if not hasattr(value, "id"):
            return value
        return {
            "podclub_id": value.podclub_id,
            "title": value.title,
            "description": value.description,
            "cover_url": value.cover_url,
            "is_active": value.is_active,
            "id": value.id,
            "uid": value.uid,
            "creator_id": value.creator_id,
            "created_at": value.created_at,
            "updated_at": value.updated_at,
            "creator": value.creator,
            "episode_count": getattr(value, "episode_count", 0),
            "podclub": value.podclub,
        }

    model_config = {"from_attributes": True}
