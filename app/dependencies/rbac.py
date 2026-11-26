from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies.auth import get_current_user
from app.models.permissions import Permissions
from app.models.role_permissions import RolePermission
from app.models.roles import RoleScope
from app.models.users import Users


def require_permission(permission_name: str):
    def dependency(
        db: Session = Depends(get_db),
        current_user: Users = Depends(get_current_user),
    ):
        if (
            not current_user.role
            or not current_user.role.active
            or current_user.role.scope != RoleScope.PLATFORM
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User has no active platform role assigned",
            )

        # Super admin bypasses platform permission checks by role name.
        if current_user.role.name == "super_admin":
            return True

        perms = (
            db.query(Permissions.name)
            .join(RolePermission, RolePermission.permission_id == Permissions.id)
            .filter(RolePermission.role_id == current_user.role_id)
            .all()
        )

        user_permissions = {p[0] for p in perms}

        if permission_name not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission_name}",
            )

        return True

    return dependency
