from uuid import UUID

from pydantic import BaseModel


class UserBrief(BaseModel):
    id: int
    uid: UUID
    username: str
    avatar_url: str | None = None

    model_config = {"from_attributes": True}


class ClubBrief(BaseModel):
    id: int
    uid: UUID
    name: str
    cover_url: str | None = None

    model_config = {"from_attributes": True}


class PodcastBrief(BaseModel):
    id: int
    uid: UUID
    title: str

    model_config = {"from_attributes": True}
