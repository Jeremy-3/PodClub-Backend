from pydantic import BaseModel, EmailStr, field_validator
from app.utils.validate import validate_password


class Login(BaseModel):
    email: EmailStr
    password: str


class LoginVerify(BaseModel):
    email: EmailStr
    otp: int


class Token(BaseModel):
    email: str
    access_token: str
    token_type: str = "bearer"
