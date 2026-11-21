from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr
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


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    avatar_url: Optional[str] = None
    role_id: Optional[int] = None
    is_active: Optional[bool] = None
    banned_at: Optional[datetime] = None


class UserOut(UserBase):
    id: int
    uid: UUID
    banned_at: Optional[datetime] = None
    role: Optional[RoleOut] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
