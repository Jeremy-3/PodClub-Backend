from sqlalchemy.orm import Session, joinedload
from fastapi import HTTPException, status
from app.models.role_permissions import RolePermission
from app.models.roles import Roles
from app.models.permissions import Permissions
from app.schema.role_permission import RolePermissionAssign, RolePermissionDeassignOut
from app.crud.base import CRUDBase

MODEL = RolePermission


class CRUDRolePermission(CRUDBase[MODEL, RolePermissionAssign]):
    """RBAC role-permission assignment logic"""

    def assign_permissions(
        self, db: Session, record_in: RolePermissionAssign
    ) -> list[int]:
        assigned = []
        try:
            for permission_id in record_in.permissions_id:
                exists = self.get_record_by_fields(
                    db,
                    {
                        "role_id": record_in.role_id,
                        "permission_id": permission_id,
                    },
                )
                if not exists:
                    rp = RolePermission(
                        role_id=record_in.role_id,
                        permission_id=permission_id,
                    )
                    db.add(rp)
                    assigned.append(permission_id)
            db.commit()
            return assigned
        except Exception:
            db.rollback()
            raise

    def deassign_permissions(
        self, db: Session, record_in: RolePermissionAssign
    ) -> RolePermissionDeassignOut:
        removed = []
        not_found = []
        try:
            for permission_id in record_in.permissions_id:
                rp = self.get_record_by_fields(
                    db,
                    {
                        "role_id": record_in.role_id,
                        "permission_id": permission_id,
                    },
                )
                if rp:
                    db.delete(rp)
                    removed.append(permission_id)
                else:
                    not_found.append(permission_id)
            db.commit()
            return RolePermissionDeassignOut(
                removed=removed,
                not_found=not_found,
                detail=f"Removed {len(removed)} permissions. {len(not_found)} not found.",
            )
        except Exception:
            db.rollback()
            raise

    def get_role_with_permissions(self, db: Session, role_id: int) -> Roles:
        role = (
            db.query(Roles)
            .options(
                joinedload(Roles.role_permissions).joinedload(RolePermission.permission)
            )
            .filter(Roles.id == role_id)
            .first()
        )
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found",
            )
        return role


crud_role_permission = CRUDRolePermission(MODEL)
