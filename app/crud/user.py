from datetime import datetime, timezone
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload
from app.core.security import (
    hash_password as generate_password_hash,
    verify_password,
)
from app.crud.base import CRUDBase
from app.models.users import Users
from app.models.roles import Roles
from app.schema.auth import RegisterIn
from app.schema.user import (
    UserAdminUpdate,
    UserCreate,
    UserCreateDB,
    PasswordChangeIn,
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

    def read_filtered(
        self,
        db: Session,
        page: int,
        limit: int,
        search: str | None = None,
        role: str | None = None,
        banned: bool | None = None,
    ) -> tuple[list[Users], int]:
        query = db.query(MODEL)
        if search:
            pattern = f"%{search}%"
            query = query.filter(
                or_(
                    MODEL.username.ilike(pattern),
                    MODEL.email.ilike(pattern),
                )
            )
        if role:
            query = query.join(Roles, MODEL.role_id == Roles.id).filter(
                func.lower(Roles.name) == role.lower()
            )
        if banned is not None:
            query = query.filter(
                MODEL.banned_at.is_not(None)
                if banned
                else MODEL.banned_at.is_(None)
            )

        total = query.with_entities(func.count(MODEL.id)).scalar()
        records = (
            query.options(joinedload(MODEL.role))
            .order_by(MODEL.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return records, total

    def search_active_users(
        self, db: Session, query_text: str, limit: int = 10
    ) -> list[Users]:
        pattern = f"%{query_text}%"
        return (
            db.query(MODEL)
            .filter(
                MODEL.is_active.is_(True),
                MODEL.banned_at.is_(None),
                or_(
                    MODEL.username.ilike(pattern),
                    MODEL.email.ilike(pattern),
                ),
            )
            .order_by(MODEL.username.asc(), MODEL.id.asc())
            .limit(limit)
            .all()
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

    def change_password(
        self, db: Session, record: Users, payload: PasswordChangeIn
    ) -> Users:
        if not verify_password(payload.current_password, record.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )
        if verify_password(payload.new_password, record.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from the current password",
            )

        changed_at = datetime.now(timezone.utc).replace(microsecond=0)
        record.password_hash = generate_password_hash(payload.new_password)
        record.password_changed_at = changed_at
        db.commit()
        db.refresh(record)
        return record
    
    

    # def delete_user(self, db: Session, uid: UUID):
    #     record = self.get_record_by_field(db, "uid", uid)
    #     if not record:
    #         raise HTTPException(
    #             status_code=status.HTTP_404_NOT_FOUND,
    #             detail="User not found",
    #         )

    #     self.delete(db, record.id)


crud_user = CRUDUser(MODEL)
