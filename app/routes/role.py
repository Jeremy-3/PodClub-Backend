from uuid import UUID
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.crud.user import crud_user
from app.schemas.user import UserCreate, UserUpdate, UserOut
from app.schemas.response import ResponseModel

router = APIRouter(prefix="/users", tags=["Users"])


@router.post(
    "",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission("user.create"))],
)
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    new_user = crud_user.create_user(db, payload)

    return ResponseModel(data=new_user, message="New User created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[UserOut]],
    dependencies=[Depends(require_permission("users.view_all"))],
)
def get_all_users(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    users, total = crud_user.read(db, page=page, limit=limit)

    return ResponseModel(
        success=True, data=users, total=total, message="Users retrieved successfully"
    )


@router.put(
    "/{uid}",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission("user.update"))],
)
def update_user(payload: UserUpdate, uid: UUID, db: Session = Depends(get_db)):
    user = crud_user.update_user(db, uid, payload)

    return ResponseModel(data=user, message="User updated successfully")


@router.get(
    "/{uid}",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission("user.view_one"))],
)
def get_one_user(uid: UUID, db: Session = Depends(get_db)):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return ResponseModel(data=UserOut, message="User retrieved successfully")
