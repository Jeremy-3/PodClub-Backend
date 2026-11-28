from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import (
    MESSAGE_CREATE,
    MESSAGE_DELETE_ANY,
    MESSAGE_DELETE_OWN,
    MESSAGE_EDIT_OWN,
    MESSAGE_READ,
)
from app.crud.message import crud_message
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.message import Messages
from app.models.podclubs import PodClubs
from app.schema.message import MessageCreate, MessageOut, MessageUpdate
from app.schema.response import ResponseModel
from app.services.media import delete_object, extract_object_path, validate_media_reference
from app.services.websockets import connection_manager

router = APIRouter(prefix="/messages", tags=["Messages"])


def _message_out(record) -> MessageOut:
    message, reply_count = record
    return MessageOut.model_validate(message).model_copy(
        update={"reply_count": reply_count}
    )


def _get_visible_club(db: Session, access: Access, podclub_id: int) -> PodClubs:
    club = crud_podclub.get(db, podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _get_message_and_club(
    db: Session, access: Access, uid: UUID
) -> tuple[Messages, PodClubs]:
    record = crud_message.get_with_reply_count(db, uid)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )
    message, _ = record
    club = _get_visible_club(db, access, message.podclub_id)
    return message, club


@router.post("", response_model=ResponseModel[MessageOut])
async def create_message(
    payload: MessageCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, payload.podclub_id)
    access.require(MESSAGE_CREATE, club)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if payload.parent_message_id is not None:
        parent = crud_message.get(db, payload.parent_message_id)
        if parent is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent message not found",
            )
        if parent.podclub_id != club.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Parent message must belong to the same PodClub",
            )

    create_payload = payload
    if payload.image_url is not None:
        create_payload = payload.model_copy(
            update={
                "image_url": validate_media_reference(
                    "image",
                    payload.image_url,
                    access.user.id,
                    club.id,
                )
            }
        )

    message = crud_message.create_message(
        db, create_payload, sender_id=access.user.id
    )
    enriched = crud_message.get_with_reply_count(db, message.uid)
    output = _message_out(enriched)
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {"type": "message.created", "data": output.model_dump(mode="json")},
    )
    return ResponseModel(
        data=output,
        message="Message created successfully",
    )


@router.get("", response_model=ResponseModel[list[MessageOut]])
def get_all_messages(
    podclub_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    after_id: int | None = Query(None, ge=1),
    before_id: int | None = Query(None, ge=1),
):
    club = _get_visible_club(db, access, podclub_id)
    access.require(MESSAGE_READ, club)
    messages, total = crud_message.read_for_club(
        db,
        podclub_id=podclub_id,
        page=page,
        limit=limit,
        after_id=after_id,
        before_id=before_id,
    )
    return ResponseModel(
        data=[_message_out(message) for message in messages],
        total=total,
        message="Messages retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[MessageOut])
def get_message(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    record = crud_message.get_with_reply_count(db, uid)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )
    message, _ = record
    club = _get_visible_club(db, access, message.podclub_id)
    access.require(MESSAGE_READ, club)
    return ResponseModel(
        data=_message_out(record),
        message="Message retrieved successfully",
    )


@router.put("/{uid}", response_model=ResponseModel[MessageOut])
async def update_message(
    uid: UUID,
    payload: MessageUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    message, club = _get_message_and_club(db, access, uid)
    if access.user is None or message.sender_id != access.user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only edit your own messages",
        )
    access.require(MESSAGE_EDIT_OWN, club)

    update_payload = payload
    if payload.image_url is not None:
        old_url = message.image_url
        update_payload = payload.model_copy(
            update={
                "image_url": validate_media_reference(
                    "image",
                    payload.image_url,
                    access.user.id,
                    club.id,
                )
            }
        )
    else:
        old_url = None

    updated_message = crud_message.update_message(db, uid, update_payload)
    if old_url and old_url != updated_message.image_url:
        path = extract_object_path(old_url)
        if path is not None:
            delete_object(path)
    enriched = crud_message.get_with_reply_count(db, updated_message.uid)
    output = _message_out(enriched)
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {"type": "message.updated", "data": output.model_dump(mode="json")},
    )
    return ResponseModel(
        data=output,
        message="Message updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
async def delete_message(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    message, club = _get_message_and_club(db, access, uid)
    if not access.can_own_or_any(
        MESSAGE_DELETE_OWN,
        MESSAGE_DELETE_ANY,
        club,
        message.sender_id,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Missing permission: {MESSAGE_DELETE_OWN} "
                f"or {MESSAGE_DELETE_ANY}"
            ),
        )

    image_url = message.image_url
    crud_message.delete_message(db, uid)
    if image_url:
        path = extract_object_path(image_url)
        if path is not None:
            delete_object(path)
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {"type": "message.deleted", "data": {"id": message.id, "uid": str(message.uid)}},
    )
    return ResponseModel(message="Message deleted successfully")
