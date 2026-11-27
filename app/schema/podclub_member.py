from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

# from app.schema.user import UserOut
# from app.schema.podclub import PodClubOut

class PodClubMemberBase(BaseModel):
    # user: UserOut
    # podclub: PodClubOut
    podclub_id: int
    user_id: int


class PodClubMemberCreate(PodClubMemberBase):
    model_config = {"extra": "forbid"}


class PodClubMemberCreateDB(PodClubMemberCreate):
    role_id: int


class PodClubMemberUpdate(BaseModel):
    role: Literal["club_moderator", "club_member"]

    model_config = {"extra": "forbid"}


class PodClubMemberOut(PodClubMemberBase):
    id: int
    uid: UUID
    joined_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
