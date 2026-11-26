from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from app.models.reports import ReportStatus

class ReportBase(BaseModel):
    reporter_id: Optional[int] = None
    reported_user_id: Optional[int] = None
    reason: str
    message_id: Optional[int] = None
    podclub_id: Optional[int] = None
    status: ReportStatus = ReportStatus.PENDING
    reviewed_by_id: Optional[int] = None


class ReportCreate(BaseModel):
    reported_user_id: Optional[int] = None
    reason: str
    message_id: Optional[int] = None
    podclub_id: Optional[int] = None

    model_config = {"extra": "forbid"}


class ReportCreateDB(ReportCreate):
    reporter_id: int
    status: ReportStatus = ReportStatus.PENDING


class ReportUpdate(BaseModel):
    status: ReportStatus

    model_config = {"extra": "forbid"}


class ReportOut(ReportBase):
    id: int
    uid: UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
