from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class PodClubBanCreate(BaseModel):
    user_id: int
    reason: Optional[str] = None

    model_config = {"extra": "forbid"}


class PodClubBanCreateDB(PodClubBanCreate):
    podclub_id: int
    banned_by_id: int


class PodClubBanOut(BaseModel):
    id: int
    uid: UUID
    podclub_id: int
    user_id: int
    banned_by_id: Optional[int] = None
    reason: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}
