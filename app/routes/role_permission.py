from app.crud.role_permission import crud_role_permission
from app.schemas.role_permission import (
    RolePermissionAssign,
    RoleWithPermissionsOut,
)
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, status
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schemas.response import ResponseModel
from uuid import UUID

router = APIRouter(prefix="/role-permissions", tags=["role-permissions"])

@router.post(
    "/assign",
    response_model=ResponseModel,
    dependencies=[Depends(require_permission("permissions.manage"))]
)
def assign_permission_to_role(
    record_in: RolePermissionAssign,
    db: Session = Depends(get_db)
):
    assigned = crud_role_permission.assign_permissions(db, record_in)
    return ResponseModel(data=assigned, message=f"Assigned {len(assigned)} permissions")


@router.post(
    "/deassign",
    response_model=ResponseModel,
    dependencies=[Depends(require_permission("permissions.manage"))]
)
def deassign_permission_from_role(
    record_in: RolePermissionAssign,
    db: Session = Depends(get_db)
):
    result = crud_role_permission.deassign_permissions(db, record_in)
    return ResponseModel(data=result, message=result.detail)


@router.get(
    "/role/{role_id}",
    response_model=ResponseModel,
    dependencies=[Depends(require_permission("roles.view"))]
)
def get_role_with_permissions(role_id: int, db: Session = Depends(get_db)):
    role = crud_role_permission.get_role_with_permissions(db, role_id)
    return ResponseModel(
        data=RoleWithPermissionsOut.from_role(role), 
        message="Role with permissions retrieved successfully"
    )