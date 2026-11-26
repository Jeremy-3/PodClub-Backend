from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import hash_password as generate_password_hash
from app.crud.base import CRUDBase
from app.models.users import Users
from app.schema.auth import RegisterIn
from app.schema.user import (
    UserAdminUpdate,
    UserCreate,
    UserCreateDB,
    UserProfileUpdate,
)


MODEL = Users


class CRUDUser(CRUDBase[MODEL, UserCreateDB]):
    """CRUD operations for User model"""

    def _ensure_unique_credentials(self, db: Session, username: str, email: str):
        if self.get_record_by_field(db, "email", email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        if self.get_record_by_field(db, "username", username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered",
            )

    def create_user(self, db: Session, record_create: UserCreate):
        self._ensure_unique_credentials(
            db, record_create.username, record_create.email
        )

        record_data = record_create.model_dump()
        record_data["password_hash"] = generate_password_hash(
            record_data.pop("password")
        )
        db_obj = UserCreateDB(**record_data)

        return self.create(db, db_obj)

    def register_user(
        self, db: Session, record_create: RegisterIn, role_id: int
    ) -> Users:
        self._ensure_unique_credentials(
            db, record_create.username, record_create.email
        )
        db_obj = UserCreateDB(
            username=record_create.username,
            email=record_create.email,
            password_hash=generate_password_hash(record_create.password),
            role_id=role_id,
        )
        return self.create(db, db_obj)

    def update_user(self, db: Session, uid: UUID, record_in: UserAdminUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return self.update(db, record, record_in)

    def ban_user(self, db: Session, record: Users) -> Users:
        return self.update(
            db,
            record,
            {"banned_at": datetime.now(timezone.utc)},
        )

    def unban_user(self, db: Session, record: Users) -> Users:
        return self.update(db, record, {"banned_at": None})

    def update_user_profile(
        self, db: Session, uid: UUID, record_in: UserProfileUpdate
    ) -> Users:
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        update_data = record_in.model_dump(exclude_unset=True)
        if update_data.get("username") is None:
            update_data.pop("username", None)
        if update_data.get("username") and update_data["username"] != record.username:
            existing_username = self.get_record_by_field(
                db, "username", update_data["username"]
            )
            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already registered",
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
