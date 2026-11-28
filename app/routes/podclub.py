from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.perm_names import (
    CLUB_CREATE,
    CLUB_DELETE,
    CLUB_READ_PRIVATE,
    CLUB_UPDATE,
)
from app.core.rate_limit import limiter
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.podclubs import PodClubs
from app.schema.podclub import (
    PodClubCreate,
    PodClubMyPermissionsOut,
    PodClubOut,
    PodClubUpdate,
)
from app.schema.response import ResponseModel
from app.services.media import delete_object, extract_object_path, validate_media_reference

router = APIRouter(prefix="/podclubs", tags=["PodClubs"])
_UNSET_ROLE = object()


def _get_visible_club(db: Session, access: Access, uid: UUID) -> PodClubs:
    club = crud_podclub.get_record_by_field(db, "uid", uid)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _my_club_role(club: PodClubs, access: Access) -> str | None:
    if access.user is None:
        return None
    if club.owner_id == access.user.id:
        return "club_owner"
    role = access.club_role(club)
    return role.name if role is not None else None


def _podclub_out(
    club: PodClubs,
    access: Access,
    member_count: int = 0,
    my_role=_UNSET_ROLE,
) -> PodClubOut:
    return PodClubOut.model_validate(club).model_copy(
        update={
            "my_role": (
                _my_club_role(club, access)
                if my_role is _UNSET_ROLE
                else my_role
            ),
            "member_count": member_count,
        }
    )


@router.post("", response_model=ResponseModel[PodClubOut])
def create_podclub(
    payload: PodClubCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    access.require(CLUB_CREATE)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    create_payload = payload
    if payload.cover_url is not None:
        create_payload = payload.model_copy(
            update={
                "cover_url": validate_media_reference(
                    "club_cover",
                    payload.cover_url,
                    access.user.id,
                    podclub_id=None,
                )
            }
        )

    podclub = crud_podclub.create_podclub(
        db, create_payload, owner_id=access.user.id
    )
    return ResponseModel(
        data=_podclub_out(podclub, access),
        message="PodClub created successfully",
    )


@router.get("", response_model=ResponseModel[list[PodClubOut]])
def get_all_podclubs(
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    mine: bool = Query(False),
    search: str | None = Query(None, max_length=100),
    sort: Literal["newest", "name"] = Query("newest"),
):
    if mine and access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication is required for mine=true",
        )
    podclubs, total = crud_podclub.read_for_user(
        db,
        user_id=access.user.id if access.user is not None else None,
        can_read_private=access.can(CLUB_READ_PRIVATE),
        page=page,
        limit=limit,
        mine=mine,
        search=search,
        sort=sort,
    )
    return ResponseModel(
        data=[
            _podclub_out(club, access, member_count=count, my_role=role)
            for club, count, role in podclubs
        ],
        total=total,
        message="PodClubs retrieved successfully",
    )


@router.get("/public", response_model=ResponseModel[list[PodClubOut]])
@limiter.limit(settings.PUBLIC_PODCLUBS_RATE_LIMIT)
def get_public_podclubs(
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    search: str | None = Query(None, max_length=100),
    sort: Literal["newest", "name"] = Query("newest"),
):
    podclubs, total = crud_podclub.read_for_user(
        db,
        user_id=None,
        can_read_private=False,
        page=page,
        limit=limit,
        search=search,
        sort=sort,
    )
    return ResponseModel(
        data=[
            PodClubOut.model_validate(club).model_copy(
                update={"my_role": None, "member_count": member_count}
            )
            for club, member_count, _ in podclubs
        ],
        total=total,
        message="Public PodClubs retrieved successfully",
    )


@router.get(
    "/{uid}/my-permissions",
    response_model=ResponseModel[PodClubMyPermissionsOut],
)
def get_my_podclub_permissions(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    permissions = access.platform_perms | access.club_perms(club)
    result = PodClubMyPermissionsOut(
        role=_my_club_role(club, access),
        permissions=sorted(permissions),
    )
    return ResponseModel(
        data=result,
        message="PodClub permissions retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[PodClubOut])
def get_podclub(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    return ResponseModel(
        data=_podclub_out(
            club, access, member_count=crud_podclub.get_member_count(db, club.id)
        ),
        message="PodClub retrieved successfully",
    )


@router.put("/{uid}", response_model=ResponseModel[PodClubOut])
def update_podclub(
    uid: UUID,
    payload: PodClubUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    access.require(CLUB_UPDATE, club)
    update_payload = payload
    if payload.cover_url is not None:
        old_url = club.cover_url
        update_payload = payload.model_copy(
            update={
                "cover_url": validate_media_reference(
                    "club_cover",
                    payload.cover_url,
                    access.user.id,
                    club.id,
                )
            }
        )
    else:
        old_url = None

    podclub = crud_podclub.update_podclub(db, uid, update_payload)
    if old_url and old_url != podclub.cover_url:
        path = extract_object_path(old_url)
        if path is not None:
            delete_object(path)
    return ResponseModel(
        data=_podclub_out(
            podclub,
            access,
            member_count=crud_podclub.get_member_count(db, podclub.id),
        ),
        message="PodClub updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_podclub(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, uid)
    access.require(CLUB_DELETE, club)
    crud_podclub.delete_podclub(db, uid)
    return ResponseModel(message="PodClub deleted successfully")
