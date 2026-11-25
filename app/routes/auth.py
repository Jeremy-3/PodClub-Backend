from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import verify_password, create_access_token
from app.crud.user import crud_user
from app.schema.user import UserCreate, UserOut
from app.dependencies.auth import get_db
from app.schema.response import ResponseModel

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=ResponseModel)
def login(user_login: Login, db: Session = Depends(get_db)):
    """Login endpoint"""
    # Check if user exists
    user = crud_user.get_record_by_field(db, "email", user_login.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Verify password
    if not verify_password(user_login.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    # Check if user is active
    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive"
        )

    # Get role name (handle if role is object or None)
    role_name = user.role.name if user.role else "GUEST"
    guest = db.query(Guests).filter(Guests.user_id == user.id).first()

    # Get permissions (handle if not available)
    permissions = []
    if hasattr(user, "role") and user.role:
        # Get permissions from role
        from app.models.role_permissions import RolePermission
        from app.models.permissions import Permissions

        role_perms = (
            db.query(Permissions)
            .join(RolePermission)
            .filter(RolePermission.role_id == user.role_id)
            .all()
        )

        permissions = [perm.name for perm in role_perms]

    # Create access token
    access_token = create_access_token(
        user_id=user.id,
        name=user.name,
        email=user.email,
        phone_number=user.phone_number,
        role=role_name,
        permissions=permissions,
    )

    return ResponseModel(
        success=True,
        data={
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "uid": str(user.uid),
                "name": user.name,
                "email": user.email,
                "role_id": user.role_id,
                "role": role_name,
                "guest_id": guest.id if guest else None,
            },
        },
        message="Login successful",
    )


@router.post("/logout", response_model=ResponseModel)
def logout():
    """Logout endpoint"""

    return ResponseModel(success=True, data=None, message="Logout successful")


@router.post("/signup", response_model=ResponseModel[UserOut])
def signup(user_create: UserCreate, db: Session = Depends(get_db)):
    """Public signup endpoint"""

    # Check if email already exists
    existing_user = crud_user.get_record_by_field(db, "email", user_create.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    # Default role assignment (customer)
    # if not user_create.role_id:
    #     from app.models.roles import Roles

    #     role = db.query(Roles).filter(Roles.name == "customer").first()
    #     if role:
    #         user_create.role_id = role.id

    new_user = crud_user.create_user(db, user_create)
    # guest = crud_user.create_guest_profile(
    #     db,
    #     GuestCreate(user_id=new_user.id),
    # )

    return ResponseModel(
        success=True,
        data=new_user,
        message="User registered successfully",
    )