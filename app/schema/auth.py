from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schema.user import UserOut
from app.utils.validate import validate_password


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str

    model_config = {"extra": "forbid"}

    @field_validator("password")
    @classmethod
    def validate_password_input(cls, value: str) -> str:
        validate_password(value)
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password cannot exceed 72 bytes")
        return value


class AuthMeOut(BaseModel):
    user: UserOut
    role: str | None
    permissions: list[str]
