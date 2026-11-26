from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class PodClubMemberBase(BaseModel):
    podclub_id: int
    user_id: int


class PodClubMemberCreate(PodClubMemberBase):
    joined_at: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class PodClubMemberUpdate(BaseModel):
    podclub_id: Optional[int] = None
    user_id: Optional[int] = None
    joined_at: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class PodClubMemberOut(PodClubMemberBase):
    id: int
    uid: UUID
    joined_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
