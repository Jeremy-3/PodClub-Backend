from app.models.podclub_members import PodClubMembers
from app.models.role_permissions import RolePermission
from app.models.roles import RoleScope, Roles
from app.models.users import Users
from app.schema.role import RoleCreate,RoleUpdate
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.crud.base import CRUDBase
from uuid import UUID

MODEL = Roles

class CRUDRole(CRUDBase[MODEL,RoleCreate]):
    """CRUD operations for Role model"""

    def get_by_name_and_scope(
        self, db: Session, name: str, scope: RoleScope
    ) -> Roles | None:
        return (
            db.query(MODEL)
            .filter(MODEL.name == name, MODEL.scope == scope)
            .one_or_none()
        )

    def create_role(self, db:Session, record_create:RoleCreate):
        existing_record = self.get_record_by_field(db, "name", record_create.name)
        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role name already exists",
            )
        
        return self.create(db, record_create)
    
    def update_role(self, db:Session, uid:UUID, record_in:RoleUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found",
            )
        if (
            record.is_system
            and record_in.name is not None
            and record_in.name != record.name
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="System roles cannot be renamed",
            )
        if record_in.name and record_in.name != record.name:
            existing_record = self.get_record_by_field(db, "name", record_in.name)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role name already exists",
                )

        return self.update(db, record, record_in)

    def delete_role(self, db:Session, uid:UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Role not found",
            )

        if record.is_system:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="System roles cannot be deleted",
            )

        assigned_to_user = (
            db.query(Users.id).filter(Users.role_id == record.id).first()
        )
        assigned_to_member = (
            db.query(PodClubMembers.id)
            .filter(PodClubMembers.role_id == record.id)
            .first()
        )
        if assigned_to_user is not None or assigned_to_member is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Role is assigned to users or club members and cannot be deleted",
            )

        db.query(RolePermission).filter(
            RolePermission.role_id == record.id
        ).delete(synchronize_session=False)
        self.delete(db, record.id)
    
crud_role = CRUDRole(MODEL)