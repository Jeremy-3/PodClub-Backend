from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.message import crud_message
from app.db.session import get_db
from app.dependencies.auth import get_current_user
from app.dependencies.rbac import require_permission
from app.models.users import Users
from app.schema.message import MessageCreate, MessageOut, MessageUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/messages", tags=["Messages"])


@router.post(
    "",
    response_model=ResponseModel[MessageOut],
    dependencies=[Depends(require_permission("message.create"))],
)
def create_message(
    payload: MessageCreate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    message = crud_message.create_message(db, payload, sender_id=current_user.id)
    return ResponseModel(data=message, message="Message created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[MessageOut]],
    dependencies=[Depends(require_permission("messages.view_all"))],
)
def get_all_messages(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    messages, total = crud_message.read(db, page=page, limit=limit)
    return ResponseModel(
        data=messages, total=total, message="Messages retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[MessageOut],
    dependencies=[Depends(require_permission("message.view_one"))],
)
def get_message(uid: UUID, db: Session = Depends(get_db)):
    message = crud_message.get_record_by_field(db, "uid", uid)
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Message not found"
        )
    return ResponseModel(data=message, message="Message retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[MessageOut],
    dependencies=[Depends(require_permission("message.update"))],
)
def update_message(uid: UUID, payload: MessageUpdate, db: Session = Depends(get_db)):
    message = crud_message.update_message(db, uid, payload)
    return ResponseModel(data=message, message="Message updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("message.delete"))],
)
def delete_message(uid: UUID, db: Session = Depends(get_db)):
    crud_message.delete_message(db, uid)
    return ResponseModel(message="Message deleted successfully")
