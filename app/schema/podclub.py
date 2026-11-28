from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel

from app.schema.brief import UserBrief


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
    owner: Optional[UserBrief] = None
    my_role: Optional[Literal["club_owner", "club_moderator", "club_member"]] = None
    member_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PodClubMyPermissionsOut(BaseModel):
    role: Optional[Literal["club_owner", "club_moderator", "club_member"]] = None
    permissions: list[str]
