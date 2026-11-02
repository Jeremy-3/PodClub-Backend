from app.models.roles import Roles
from app.schema.role import RoleCreate,RoleUpdate
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.crud.base import CRUDBase
from uuid import UUID

MODEL = Roles

class CRUDRole(CRUDBase[MODEL,RoleCreate]):
    """CRUD operations for Role model"""

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
        
        db.delete(record)
        db.commit()
    
crud_role = CRUDRole(MODEL)