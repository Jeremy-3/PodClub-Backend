from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, model_validator

from app.schema.brief import UserBrief


class MessageParentBrief(BaseModel):
    id: int
    uid: UUID
    body: Optional[str] = None
    sender_username: Optional[str] = None


class MessageBase(BaseModel):
    podclub_id: Optional[int] = None
    parent_message_id: Optional[int] = None
    body: Optional[str] = None
    image_url: Optional[str] = None


class MessageCreate(MessageBase):
    podclub_id: int

    model_config = {"extra": "forbid"}


class MessageCreateDB(MessageCreate):
    sender_id: int


class MessageUpdate(BaseModel):
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
    sender: Optional[UserBrief] = None
    reply_count: int = 0
    parent: Optional[MessageParentBrief] = None

    @model_validator(mode="before")
    @classmethod
    def enrich_from_orm(cls, value):
        if isinstance(value, dict):
            return value

        message, reply_count = value if isinstance(value, tuple) else (value, 0)
        if not hasattr(message, "id"):
            return value

        parent_message = message.parent_message
        parent = None
        if parent_message is not None:
            parent_body = (
                None if parent_message.is_deleted else parent_message.body
            )
            parent = {
                "id": parent_message.id,
                "uid": parent_message.uid,
                "body": parent_body[:120] if parent_body is not None else None,
                "sender_username": (
                    parent_message.sender.username
                    if parent_message.sender is not None
                    else None
                ),
            }

        return {
            "podclub_id": message.podclub_id,
            "parent_message_id": message.parent_message_id,
            "body": None if message.is_deleted else message.body,
            "image_url": None if message.is_deleted else message.image_url,
            "id": message.id,
            "uid": message.uid,
            "sender_id": message.sender_id,
            "is_edited": message.is_edited,
            "is_deleted": message.is_deleted,
            "created_at": message.created_at,
            "updated_at": message.updated_at,
            "sender": message.sender,
            "reply_count": reply_count,
            "parent": parent,
        }

    model_config = {"from_attributes": True}
