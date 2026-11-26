from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.invite import crud_invite
from app.db.session import get_db
from app.dependencies.auth import get_current_user
from app.dependencies.rbac import require_permission
from app.models.users import Users
from app.schema.invite import InviteCreate, InviteOut, InviteUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/invites", tags=["Invites"])


@router.post(
    "",
    response_model=ResponseModel[InviteOut],
    dependencies=[Depends(require_permission("invite.create"))],
)
def create_invite(
    payload: InviteCreate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    invite = crud_invite.create_invite(db, payload, invited_by_id=current_user.id)
    return ResponseModel(data=invite, message="Invite created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[InviteOut]],
    dependencies=[Depends(require_permission("invites.view_all"))],
)
def get_all_invites(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    invites, total = crud_invite.read(db, page=page, limit=limit)
    return ResponseModel(
        data=invites, total=total, message="Invites retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[InviteOut],
    dependencies=[Depends(require_permission("invite.view_one"))],
)
def get_invite(uid: UUID, db: Session = Depends(get_db)):
    invite = crud_invite.get_record_by_field(db, "uid", uid)
    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found"
        )
    return ResponseModel(data=invite, message="Invite retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[InviteOut],
    dependencies=[Depends(require_permission("invite.update"))],
)
def update_invite(uid: UUID, payload: InviteUpdate, db: Session = Depends(get_db)):
    invite = crud_invite.update_invite(db, uid, payload)
    return ResponseModel(data=invite, message="Invite updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("invite.delete"))],
)
def delete_invite(uid: UUID, db: Session = Depends(get_db)):
    crud_invite.delete_invite(db, uid)
    return ResponseModel(message="Invite deleted successfully")
