from app.crud.permission import crud_permission
from app.schemas.permission import PermissionCreate, PermissionUpdate, PermissionOut
from app.dependencies.rbac import require_permission
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.response import ResponseModel
from uuid import UUID

router = APIRouter(prefix="/permissions", tags=["permissions"])


@router.post(
    "",
    response_model=ResponseModel[PermissionOut],
    dependencies=[Depends(require_permission("permissions.manage"))],
)
def create_permission(
    permission_create: PermissionCreate, db: Session = Depends(get_db)
):
    new_permission = crud_permission.create_permission(db, permission_create)
    return ResponseModel(data=new_permission, message="Permission created successfully")
 

@router.get(
    "",
    response_model=ResponseModel[list[PermissionOut]],
    dependencies=[Depends(require_permission("permissions.manage"))],
)
def get_all_permissions(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    permissions, total = crud_permission.read(db,page=page, limit=limit)

    return ResponseModel(
        data=permissions, total=total, message="Permissions retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel,
    dependencies=[Depends(require_permission("permissions.manage"))],
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
    dependencies=[Depends(require_permission("permissions.edit"))],
)
def update_permission(
    uid: UUID, permission_update: PermissionUpdate, db: Session = Depends(get_db)
):
    updated_permission = crud_permission.update_permission(db, uid, permission_update)
    return ResponseModel(
        data=updated_permission, message="Permission updated successfully"
    )