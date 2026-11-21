from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class MessageBase(BaseModel):
    podclub_id: Optional[int] = None
    sender_id: Optional[int] = None
    parent_message_id: Optional[int] = None
    body: Optional[str] = None
    image_url: Optional[str] = None


class MessageCreate(MessageBase):
    pass


class MessageUpdate(BaseModel):
    podclub_id: Optional[int] = None
    sender_id: Optional[int] = None
    parent_message_id: Optional[int] = None
    body: Optional[str] = None
    image_url: Optional[str] = None
    is_edited: Optional[bool] = None
    is_deleted: Optional[bool] = None


class MessageOut(MessageBase):
    id: int
    uid: UUID
    is_edited: bool
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
