from datetime import datetime
from pydantic import BaseModel, field_validator, EmailStr
from typing import Optional, Union
from uuid import UUID
from app.utils.validate import validate_password
from app.schema.role import RoleOut


class UserBase(BaseModel):
    name: str
    email: EmailStr
    phone_number: str
    role_id: int


class UserCreateDB(BaseModel):
    name: str
    email: EmailStr
    phone_number: Optional[str] = None
    password_hash: str
    role_id: int | None = None


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone_number: Optional[str] = None
    password: str
    role_id: int | None = None

    @field_validator("password")
    def validate_password_filed(cls, v: str) -> str:
        return validate_password(v)

    @field_validator("phone_number")
    def validate_phone_number(cls, v: str) -> str:
        if v is not None:
            return validate_kenyan_phone_number(v)
        return v


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    password: Optional[str] = None
    role_id: Optional[int] = None

    @field_validator("password")
    def validate_password_filed(cls, v: str) -> str:
        if v is not None:
            return validate_password(v)
        return v

    @field_validator("phone_number")
    def validate_phone_number(cls, v: str) -> str:
        if v is not None:
            return validate_kenyan_phone_number(v)
        return v


class UserOut(UserBase):
    id: int
    uid: UUID
    role: RoleOut = None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
    }