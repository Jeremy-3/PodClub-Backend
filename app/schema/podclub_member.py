from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, field_validator

from app.schema.brief import UserBrief

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
    user: UserBrief
    role: str

    @field_validator("role", mode="before")
    @classmethod
    def role_name(cls, value):
        return value.name if hasattr(value, "name") else value

    model_config = {"from_attributes": True}
