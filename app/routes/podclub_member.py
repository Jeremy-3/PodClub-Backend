from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.podclub_member import crud_podclub_member
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.podclub_member import (
    PodClubMemberCreate,
    PodClubMemberOut,
    PodClubMemberUpdate,
)
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podclub-members", tags=["PodClub Members"])


@router.post(
    "",
    response_model=ResponseModel[PodClubMemberOut],
    dependencies=[Depends(require_permission("podclub_member.create"))],
)
def create_podclub_member(
    payload: PodClubMemberCreate, db: Session = Depends(get_db)
):
    member = crud_podclub_member.create_podclub_member(db, payload)
    return ResponseModel(data=member, message="PodClub member created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[PodClubMemberOut]],
    dependencies=[Depends(require_permission("podclub_members.view_all"))],
)
def get_all_podclub_members(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    members, total = crud_podclub_member.read(db, page=page, limit=limit)
    return ResponseModel(
        data=members, total=total, message="PodClub members retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[PodClubMemberOut],
    dependencies=[Depends(require_permission("podclub_member.view_one"))],
)
def get_podclub_member(uid: UUID, db: Session = Depends(get_db)):
    member = crud_podclub_member.get_record_by_field(db, "uid", uid)
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="PodClub member not found"
        )
    return ResponseModel(data=member, message="PodClub member retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[PodClubMemberOut],
    dependencies=[Depends(require_permission("podclub_member.update"))],
)
def update_podclub_member(
    uid: UUID, payload: PodClubMemberUpdate, db: Session = Depends(get_db)
):
    member = crud_podclub_member.update_podclub_member(db, uid, payload)
    return ResponseModel(data=member, message="PodClub member updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("podclub_member.delete"))],
)
def delete_podclub_member(uid: UUID, db: Session = Depends(get_db)):
    crud_podclub_member.delete_podclub_member(db, uid)
    return ResponseModel(message="PodClub member deleted successfully")
