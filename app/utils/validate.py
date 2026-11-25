import re
from pydantic import EmailStr, ValidationError


def valid_email(value: str) -> bool:
    try:
        EmailStr.validate_python(value)
        return True
    except ValidationError:
        return False


def validate_password(v: str) -> str:
    if valid_email(v):
        return v

    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", v):
        raise ValueError("Password must contain at least one number")
    if not re.search(r"[\W_]", v):
        raise ValueError("Password must contain at least one special character")

    return v
