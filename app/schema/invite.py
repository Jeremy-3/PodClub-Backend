from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr


class InviteBase(BaseModel):
    podclub_id: Optional[int] = None
    email: EmailStr
    invited_by_id: Optional[int] = None
    max_uses: int = 0


class InviteCreate(InviteBase):
    token: Optional[str] = None
    expires_at: Optional[datetime] = None


class InviteUpdate(BaseModel):
    podclub_id: Optional[int] = None
    email: Optional[EmailStr] = None
    token: Optional[str] = None
    invited_by_id: Optional[int] = None
    accepted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    max_uses: Optional[int] = None
    use_count: Optional[int] = None


class InviteOut(InviteBase):
    id: int
    uid: UUID
    token: str
    accepted_at: Optional[datetime] = None
    expires_at: datetime
    use_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
