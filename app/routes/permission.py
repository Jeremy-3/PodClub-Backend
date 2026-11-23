from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.permission import crud_permission
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.permission import PermissionCreate, PermissionOut, PermissionUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.post(
    "",
    response_model=ResponseModel[PermissionOut],
    dependencies=[Depends(require_permission("permission.create"))],
)
def create_permission(
    payload: PermissionCreate, db: Session = Depends(get_db)
):
    permission = crud_permission.create_permission(db, payload)
    return ResponseModel(data=permission, message="Permission created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[PermissionOut]],
    dependencies=[Depends(require_permission("permissions.view_all"))],
)
def get_all_permissions(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    permissions, total = crud_permission.read(db, page=page, limit=limit)
    return ResponseModel(
        data=permissions, total=total, message="Permissions retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[PermissionOut],
    dependencies=[Depends(require_permission("permission.view_one"))],
)
def get_permission(uid: UUID, db: Session = Depends(get_db)):
    permission = crud_permission.get_record_by_field(db, "uid", uid)
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found"
        )
    return ResponseModel(data=permission, message="Permission retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[PermissionOut],
    dependencies=[Depends(require_permission("permission.update"))],
)
def update_permission(
    uid: UUID, payload: PermissionUpdate, db: Session = Depends(get_db)
):
    permission = crud_permission.update_permission(db, uid, payload)
    return ResponseModel(data=permission, message="Permission updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("permission.delete"))],
)
def delete_permission(uid: UUID, db: Session = Depends(get_db)):
    crud_permission.delete_permission(db, uid)
    return ResponseModel(message="Permission deleted successfully")
