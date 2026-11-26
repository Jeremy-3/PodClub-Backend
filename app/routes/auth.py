from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.security import create_access_token, verify_password
from app.crud.role import crud_role
from app.crud.role_permission import crud_role_permission
from app.crud.user import crud_user
from app.db.session import get_db
from app.dependencies.auth import get_current_user
from app.models.users import Users
from app.schema.auth import AuthMeOut, RegisterIn
from app.schema.response import ResponseModel
from app.schema.user import UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=ResponseModel[UserOut])
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    role = crud_role.get_record_by_field(db, "name", "user")
    if not role:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The 'user' role is missing. Run 'python -m app.commands.seed'.",
        )

    user = crud_user.register_user(db, payload, role.id)
    return ResponseModel(data=user, message="User registered successfully")


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    user = crud_user.get_record_by_field(db, "username", form_data.username)
    if not user:
        user = crud_user.get_record_by_field(db, "email", form_data.username)

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.banned_at is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is banned",
        )

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer",
    }


@router.get("/me", response_model=ResponseModel[AuthMeOut])
def read_current_user(
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    permissions = (
        crud_role_permission.get_permissions_for_role(db, current_user.role_id)
        if current_user.role_id is not None
        else []
    )
    role_name = current_user.role.name if current_user.role else None
    return ResponseModel(
        data=AuthMeOut(
            user=current_user,
            role=role_name,
            permissions=permissions,
        ),
        message="Current user retrieved successfully",
    )
