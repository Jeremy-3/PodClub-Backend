from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import (
    MEMBER_INVITE,
    MEMBER_READ,
    MEMBER_REMOVE,
    MEMBER_SET_ROLE,
)
from app.crud.podclub_member import crud_podclub_member
from app.crud.podclub import crud_podclub
from app.crud.podclub_ban import crud_podclub_ban
from app.crud.role import crud_role
from app.crud.user import crud_user
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.roles import RoleScope
from app.schema.podclub_member import (
    PodClubMemberCreate,
    PodClubMemberOut,
    PodClubMemberUpdate,
)
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podclub-members", tags=["PodClub Members"])


def _get_club(db: Session, podclub_id: int) -> PodClubs:
    club = crud_podclub.get(db, podclub_id)
    if club is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _require_club_permission(access: Access, club: PodClubs, permission: str) -> None:
    if not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    access.require(permission, club)


def _get_member(db: Session, uid: UUID) -> PodClubMembers:
    member = crud_podclub_member.get_with_briefs(db, uid)
    if member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub member not found",
        )
    return member


def _club_role_id(db: Session, role_name: str) -> int:
    role = crud_role.get_by_name_and_scope(db, role_name, RoleScope.CLUB)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Club role '{role_name}' not found; run the seed command",
        )
    return role.id


@router.post(
    "",
    response_model=ResponseModel[PodClubMemberOut],
)
def create_podclub_member(
    payload: PodClubMemberCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_club(db, payload.podclub_id)
    _require_club_permission(access, club, MEMBER_INVITE)

    user = crud_user.get(db, payload.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    banned = crud_podclub_ban.get_by_club_user(db, club.id, user.id)
    if banned is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is banned from this PodClub",
        )

    role_id = _club_role_id(db, "club_member")
    member = crud_podclub_member.create_podclub_member(db, payload, role_id)
    return ResponseModel(
        data=member,
        message="PodClub member created successfully",
    )


@router.get(
    "",
    response_model=ResponseModel[list[PodClubMemberOut]],
)
def get_all_podclub_members(
    podclub_id: int = Query(..., ge=1),
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    club = _get_club(db, podclub_id)
    _require_club_permission(access, club, MEMBER_READ)

    members, total = crud_podclub_member.read(
        db,
        page=page,
        limit=limit,
        relationships=["user", "role"],
        filters=[{"field": "podclub_id", "value": podclub_id}],
    )
    return ResponseModel(
        data=members,
        total=total,
        message="PodClub members retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[PodClubMemberOut])
def get_podclub_member(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    member = _get_member(db, uid)
    club = _get_club(db, member.podclub_id)
    _require_club_permission(access, club, MEMBER_READ)
    return ResponseModel(
        data=member,
        message="PodClub member retrieved successfully",
    )


@router.put("/{uid}", response_model=ResponseModel[PodClubMemberOut])
def update_podclub_member(
    uid: UUID,
    payload: PodClubMemberUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    member = _get_member(db, uid)
    club = _get_club(db, member.podclub_id)
    _require_club_permission(access, club, MEMBER_SET_ROLE)

    role_id = _club_role_id(db, payload.role)
    updated_member = crud_podclub_member.update_podclub_member_role(
        db, member, role_id
    )
    return ResponseModel(
        data=updated_member,
        message="PodClub member role updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_podclub_member(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    member = _get_member(db, uid)
    club = _get_club(db, member.podclub_id)
    if not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )

    if access.user is not None and member.user_id == access.user.id:
        if club.owner_id == access.user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The PodClub owner cannot leave the PodClub",
            )
    else:
        access.require(MEMBER_REMOVE, club)

    crud_podclub_member.delete_podclub_member(db, member)
    return ResponseModel(message="PodClub member removed successfully")
