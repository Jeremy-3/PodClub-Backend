from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.role import crud_role
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.response import ResponseModel
from app.schema.role import RoleCreate, RoleOut, RoleUpdate

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.post(
    "",
    response_model=ResponseModel[RoleOut],
    dependencies=[Depends(require_permission("role.create"))],
)
def create_role(payload: RoleCreate, db: Session = Depends(get_db)):
    role = crud_role.create_role(db, payload)
    return ResponseModel(data=role, message="Role created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[RoleOut]],
    dependencies=[Depends(require_permission("roles.view_all"))],
)
def get_all_roles(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    roles, total = crud_role.read(db, page=page, limit=limit)
    return ResponseModel(
        success=True, data=roles, total=total, message="Roles retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[RoleOut],
    dependencies=[Depends(require_permission("role.view_one"))],
)
def get_role(uid: UUID, db: Session = Depends(get_db)):
    role = crud_role.get_record_by_field(db, "uid", uid)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    return ResponseModel(data=role, message="Role retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[RoleOut],
    dependencies=[Depends(require_permission("role.update"))],
)
def update_role(uid: UUID, payload: RoleUpdate, db: Session = Depends(get_db)):
    role = crud_role.update_role(db, uid, payload)
    return ResponseModel(data=role, message="Role updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("role.delete"))],
)
def delete_role(uid: UUID, db: Session = Depends(get_db)):
    crud_role.delete_role(db, uid)
    return ResponseModel(message="Role deleted successfully")