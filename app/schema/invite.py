from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr


class InviteBase(BaseModel):
    podclub_id: Optional[int] = None
    email: EmailStr
    max_uses: int = 0


class InviteCreate(InviteBase):
    podclub_id: int
    expires_at: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class InviteCreateDB(InviteCreate):
    token: str
    invited_by_id: int
    expires_at: datetime


class InviteUpdate(BaseModel):
    expires_at: Optional[datetime] = None
    max_uses: Optional[int] = None

    model_config = {"extra": "forbid"}


class InviteOut(InviteBase):
    id: int
    uid: UUID
    invited_by_id: Optional[int] = None
    token: str
    accepted_at: Optional[datetime] = None
    expires_at: datetime
    use_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
