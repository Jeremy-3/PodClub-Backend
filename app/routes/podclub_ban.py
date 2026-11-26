from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.perm_names import MEMBER_BAN, MEMBER_UNBAN
from app.crud.podclub_ban import crud_podclub_ban
from app.crud.podclub import crud_podclub
from app.crud.user import crud_user
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.podclubs import PodClubs
from app.schema.podclub_ban import PodClubBanCreate, PodClubBanOut
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podclubs", tags=["PodClub Bans"])


def _get_visible_club(db: Session, access: Access, uid: UUID) -> PodClubs:
    club = crud_podclub.get_record_by_field(db, "uid", uid)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


@router.post(
    "/{uid}/bans",
    response_model=ResponseModel[PodClubBanOut],
)
def create_podclub_ban(
    uid: UUID,
    payload: PodClubBanCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    access.require(MEMBER_BAN, club)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    if payload.user_id == access.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot ban yourself from a PodClub",
        )
    if payload.user_id == club.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The PodClub owner cannot be banned",
        )

    user = crud_user.get(db, payload.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    ban = crud_podclub_ban.create_ban(
        db,
        podclub_id=club.id,
        user_id=user.id,
        banned_by_id=access.user.id,
        reason=payload.reason,
    )
    return ResponseModel(data=ban, message="User banned from PodClub successfully")


@router.get(
    "/{uid}/bans",
    response_model=ResponseModel[list[PodClubBanOut]],
)
def get_podclub_bans(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    access.require(MEMBER_BAN, club)
    bans = crud_podclub_ban.list_for_club(db, club.id)
    return ResponseModel(
        data=bans,
        total=len(bans),
        message="PodClub bans retrieved successfully",
    )


@router.delete(
    "/{uid}/bans/{user_id}",
    response_model=ResponseModel[None],
)
def delete_podclub_ban(
    uid: UUID,
    user_id: int,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    access.require(MEMBER_UNBAN, club)
    ban = crud_podclub_ban.get_by_club_user(db, club.id, user_id)
    if ban is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub ban not found",
        )

    crud_podclub_ban.delete_ban(db, ban)
    return ResponseModel(message="User unbanned from PodClub successfully")
