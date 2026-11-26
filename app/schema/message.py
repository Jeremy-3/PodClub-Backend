from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class MessageBase(BaseModel):
    podclub_id: Optional[int] = None
    parent_message_id: Optional[int] = None
    body: Optional[str] = None
    image_url: Optional[str] = None


class MessageCreate(MessageBase):
    model_config = {"extra": "forbid"}


class MessageCreateDB(MessageCreate):
    sender_id: int


class MessageUpdate(BaseModel):
    podclub_id: Optional[int] = None
    parent_message_id: Optional[int] = None
    body: Optional[str] = None
    image_url: Optional[str] = None

    model_config = {"extra": "forbid"}


class MessageOut(MessageBase):
    id: int
    uid: UUID
    sender_id: Optional[int] = None
    is_edited: bool
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
