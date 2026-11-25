from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import hash_password as generate_password_hash
from app.crud.base import CRUDBase
from app.models.users import Users
from app.schema.user import UserCreate, UserCreateDB, UserUpdate


MODEL = Users


class CRUDUser(CRUDBase[MODEL, UserCreateDB]):
    """CRUD operations for User model"""

    def create_user(self, db: Session, record_create: UserCreate):
        existing_email = self.get_record_by_field(db, "email", record_create.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        existing_username = self.get_record_by_field(
            db, "username", record_create.username
        )
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered",
            )

        record_data = record_create.model_dump()
        record_data["password_hash"] = generate_password_hash(record_data.pop("password"))
        db_obj = UserCreateDB(**record_data)

        return self.create(db, db_obj)

    def update_user(self, db: Session, uid: UUID, record_in: UserUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        if record_in.email and record_in.email != record.email:
            existing_email = self.get_record_by_field(db, "email", record_in.email)
            if existing_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered",
                )

        if record_in.username and record_in.username != record.username:
            existing_username = self.get_record_by_field(
                db, "username", record_in.username
            )
            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already registered",
                )

        update_data = record_in.model_dump(exclude_unset=True)
        if "password" in update_data:
            update_data["password_hash"] = generate_password_hash(
                update_data.pop("password")
            )

        return self.update(db, record, update_data)
    
    

    # def delete_user(self, db: Session, uid: UUID):
    #     record = self.get_record_by_field(db, "uid", uid)
    #     if not record:
    #         raise HTTPException(
    #             status_code=status.HTTP_404_NOT_FOUND,
    #             detail="User not found",
    #         )

    #     self.delete(db, record.id)


crud_user = CRUDUser(MODEL)
