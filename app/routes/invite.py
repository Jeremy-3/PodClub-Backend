from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import MEMBER_INVITE
from app.crud.invite import crud_invite
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.invites import Invites
from app.models.podclubs import PodClubs
from app.schema.invite import InviteCreate, InviteOut, InviteUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/invites", tags=["Invites"])


def _get_visible_club(db: Session, access: Access, podclub_id: int) -> PodClubs:
    club = crud_podclub.get(db, podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _get_invite(db: Session, uid: UUID) -> Invites:
    invite = crud_invite.get_record_by_field(db, "uid", uid)
    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invite not found",
        )
    return invite


def _require_invite_access(db: Session, access: Access, uid: UUID) -> Invites:
    invite = _get_invite(db, uid)
    club = _get_visible_club(db, access, invite.podclub_id)
    access.require(MEMBER_INVITE, club)
    return invite


@router.post("", response_model=ResponseModel[InviteOut])
def create_invite(
    payload: InviteCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, payload.podclub_id)
    access.require(MEMBER_INVITE, club)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    invite = crud_invite.create_invite(
        db, payload, invited_by_id=access.user.id
    )
    return ResponseModel(data=invite, message="Invite created successfully")


@router.get("", response_model=ResponseModel[list[InviteOut]])
def get_all_invites(
    podclub_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    club = _get_visible_club(db, access, podclub_id)
    access.require(MEMBER_INVITE, club)
    invites, total = crud_invite.read(
        db,
        page=page,
        limit=limit,
        filters=[{"field": "podclub_id", "value": podclub_id}],
    )
    return ResponseModel(
        data=invites,
        total=total,
        message="Invites retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[InviteOut])
def get_invite(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    invite = _require_invite_access(db, access, uid)
    return ResponseModel(data=invite, message="Invite retrieved successfully")


@router.put("/{uid}", response_model=ResponseModel[InviteOut])
def update_invite(
    uid: UUID,
    payload: InviteUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    _require_invite_access(db, access, uid)
    invite = crud_invite.update_invite(db, uid, payload)
    return ResponseModel(data=invite, message="Invite updated successfully")


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_invite(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    _require_invite_access(db, access, uid)
    crud_invite.delete_invite(db, uid)
    return ResponseModel(message="Invite deleted successfully")
