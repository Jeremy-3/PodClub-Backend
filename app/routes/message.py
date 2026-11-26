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

router = APIRouter(prefix="/messages", tags=["Messages"])


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
    message = crud_message.get_record_by_field(db, "uid", uid)
    if message is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )
    club = _get_visible_club(db, access, message.podclub_id)
    return message, club


@router.post("", response_model=ResponseModel[MessageOut])
def create_message(
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

    message = crud_message.create_message(
        db, payload, sender_id=access.user.id
    )
    return ResponseModel(data=message, message="Message created successfully")


@router.get("", response_model=ResponseModel[list[MessageOut]])
def get_all_messages(
    podclub_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    club = _get_visible_club(db, access, podclub_id)
    access.require(MESSAGE_READ, club)
    messages, total = crud_message.read(
        db,
        page=page,
        limit=limit,
        filters=[{"field": "podclub_id", "value": podclub_id}],
    )
    return ResponseModel(
        data=messages,
        total=total,
        message="Messages retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[MessageOut])
def get_message(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    message, club = _get_message_and_club(db, access, uid)
    access.require(MESSAGE_READ, club)
    return ResponseModel(data=message, message="Message retrieved successfully")


@router.put("/{uid}", response_model=ResponseModel[MessageOut])
def update_message(
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

    updated_message = crud_message.update_message(db, uid, payload)
    return ResponseModel(
        data=updated_message,
        message="Message updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_message(
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

    crud_message.delete_message(db, uid)
    return ResponseModel(message="Message deleted successfully")
