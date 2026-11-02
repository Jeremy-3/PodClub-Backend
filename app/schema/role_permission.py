from pydantic import BaseModel
from typing import Optional, Union, List
from datetime import datetime
from uuid import UUID

class RolePermissionBase(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionCreate(RolePermissionBase):
    pass

class RolePermissionAssign(BaseModel):
    role_id: int
    permissions_id: List[int] 

class RolePermissionDeassignOut(BaseModel):
    removed: List[int]
    not_found: List[int]
    detail: str

class RolePermissionUpdate(BaseModel):
    role_id: Optional[int] = None
    permissions_id: Optional[List[int]] = None

class RolePermissionOut(BaseModel):
    id: int
    uid: Union[str, UUID]
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}

# ── Permission shape used inside RoleWithPermissionsOut ───────────────────────
class PermissionInRole(BaseModel):
    id: int
    uid: Union[str, UUID]
    name: str
    description: Optional[str] = None
    category: Optional[str] = None          # ← real field from Permissions model

    model_config = {"from_attributes": True}

# ── Role with permissions list ────────────────────────────────────────────────
class RoleWithPermissionsOut(BaseModel):
    id: int
    uid: Union[str, UUID]
    name: str
    active: bool
    permissions: List[PermissionInRole] = []

    model_config = {"from_attributes": True}

    @classmethod
    def from_role(cls, role: object) -> "RoleWithPermissionsOut":
        """Build from a Roles ORM object with loaded role_permissions"""
        return cls(
            id=role.id,
            uid=role.uid,
            name=role.name,
            active=role.active,
            permissions=[
                PermissionInRole(
                    id=rp.permission.id,
                    uid=rp.permission.uid,
                    name=rp.permission.name,
                    description=rp.permission.description,
                    category=rp.permission.category,
                )
                for rp in role.role_permissions
                if rp.permission is not None     # guard against orphaned records
            ]
        )