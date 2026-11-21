from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class ReportBase(BaseModel):
    reporter_id: Optional[int] = None
    reported_user_id: Optional[int] = None
    reason: str
    message_id: Optional[int] = None
    podclub_id: Optional[int] = None
    status: str = "pending"
    reviewed_by_id: Optional[int] = None


class ReportCreate(BaseModel):
    reporter_id: Optional[int] = None
    reported_user_id: Optional[int] = None
    reason: str
    message_id: Optional[int] = None
    podclub_id: Optional[int] = None
    status: str = "pending"


class ReportUpdate(BaseModel):
    reporter_id: Optional[int] = None
    reported_user_id: Optional[int] = None
    reason: Optional[str] = None
    message_id: Optional[int] = None
    podclub_id: Optional[int] = None
    status: Optional[str] = None
    reviewed_by_id: Optional[int] = None


class ReportOut(ReportBase):
    id: int
    uid: UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
