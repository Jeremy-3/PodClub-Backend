from app.models.permissions import Permissions
from app.schema.permission import PermissionCreate, PermissionOut, PermissionUpdate
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.crud.base import CRUDBase
from uuid import UUID

MODEL = Permissions

class CRUDPermission(CRUDBase[MODEL,PermissionCreate]):
    """ CRUD operations for Permissions model   """
    def create_permission(self, db: Session, record_create: PermissionCreate):
        existing_record = self.get_record_by_field(db, "name", record_create.name)

        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission name already exists",
            )

        return self.create(db, record_create)


    def update_permission(self, db:Session, uid:UUID, record_in:PermissionUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found",
            )
        if record_in.name and record_in.name != record.name:
            existing_record = self.get_record_by_field(db, "name", record_in.name)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Permission name already exists",
                )
        if record_in.description and record_in.description != record.description:
            existing_record = self.get_record_by_field(db, "description", record_in.description)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Permission description already exists",
                )

        return self.update(db, record, record_in)
    
    def delete_permission(self, db:Session, uid:UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Permission not found",
            )
        
        db.delete(record)
        db.commit()

crud_permission = CRUDPermission(MODEL)