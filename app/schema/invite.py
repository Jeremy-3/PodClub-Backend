from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.schema.brief import ClubBrief


class InviteBase(BaseModel):
    podclub_id: Optional[int] = None
    email: EmailStr
    max_uses: int = Field(default=0, ge=0, description="0 means unlimited")


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
    max_uses: Optional[int] = Field(
        default=None, ge=0, description="0 means unlimited"
    )

    model_config = {"extra": "forbid"}


class InviteAcceptIn(BaseModel):
    token: str = Field(min_length=16, max_length=512)

    model_config = {"extra": "forbid"}


class InvitePreviewOut(BaseModel):
    podclub: ClubBrief
    expires_at: datetime
    remaining_uses: Optional[int] = None


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
