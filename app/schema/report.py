from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, model_validator

from app.schema.brief import ClubBrief, UserBrief
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
    reporter: Optional[UserBrief] = None
    reported_user: Optional[UserBrief] = None
    message_snippet: Optional[str] = None
    podclub: Optional[ClubBrief] = None

    @model_validator(mode="before")
    @classmethod
    def enrich_from_orm(cls, value):
        if isinstance(value, dict):
            return value
        if not hasattr(value, "id"):
            return value
        message_body = (
            value.message.body
            if value.message is not None and not value.message.is_deleted
            else None
        )
        return {
            "reporter_id": value.reporter_id,
            "reported_user_id": value.reported_user_id,
            "reason": value.reason,
            "message_id": value.message_id,
            "podclub_id": value.podclub_id,
            "status": value.status,
            "reviewed_by_id": value.reviewed_by_id,
            "id": value.id,
            "uid": value.uid,
            "created_at": value.created_at,
            "updated_at": value.updated_at,
            "reporter": value.reporter,
            "reported_user": value.reported_user,
            "message_snippet": (
                message_body[:120] if message_body is not None else None
            ),
            "podclub": value.podclub,
        }

    model_config = {"from_attributes": True}
