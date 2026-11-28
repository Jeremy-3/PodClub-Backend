from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator

from app.utils.validate import validate_password
from app.schema.role import RoleOut


class UserBase(BaseModel):
    username: str
    email: EmailStr
    avatar_url: Optional[str] = None
    role_id: Optional[int] = None
    is_active: bool = True


class UserCreateDB(BaseModel):
    username: str
    email: EmailStr
    password_hash: str
    avatar_url: Optional[str] = None
    role_id: Optional[int] = None
    is_active: bool = True
    banned_at: Optional[datetime] = None


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    avatar_url: Optional[str] = None
    role_id: Optional[int] = None
    is_active: bool = True

    model_config = {"extra": "forbid"}

    @field_validator("password")
    @classmethod
    def validate_password_input(cls, value: str) -> str:
        validate_password(value)
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password cannot exceed 72 bytes")
        return value


class UserProfileUpdate(BaseModel):
    username: Optional[str] = Field(default=None, min_length=3, max_length=50)
    avatar_url: Optional[str] = None

    model_config = {"extra": "forbid"}


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str

    model_config = {"extra": "forbid"}

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        validate_password(value)
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password cannot exceed 72 bytes")
        return value


class PasswordChangeOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserAdminUpdate(BaseModel):
    role_id: Optional[int] = None
    is_active: Optional[bool] = None

    model_config = {"extra": "forbid"}


class UserOut(UserBase):
    id: int
    uid: UUID
    banned_at: Optional[datetime] = None
    role: Optional[RoleOut] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserPublicOut(BaseModel):
    uid: UUID
    username: str
    avatar_url: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}
