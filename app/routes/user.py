from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.core.perm_names import (
    ROLE_ADMIN,
    ROLE_SUPER_ADMIN,
    USER_CREATE,
    USER_BAN,
    USER_UPDATE,
    USER_UNBAN,
    USER_VIEW_ONE,
    USERS_VIEW_ALL,
)
from app.crud.role import crud_role
from app.crud.user import crud_user
from app.db.session import get_db
from app.dependencies.auth import get_current_user
from app.dependencies.rbac import require_permission
from app.models.users import Users
from app.models.roles import RoleScope
from app.schema.response import ResponseModel
from app.schema.brief import UserBrief
from app.schema.user import (
    UserAdminUpdate,
    UserCreate,
    UserOut,
    PasswordChangeIn,
    PasswordChangeOut,
    UserProfileUpdate,
    UserPublicOut,
)
from app.services.media import delete_object, extract_object_path, validate_media_reference

router = APIRouter(prefix="/users", tags=["Users"])


def _is_super_admin(user: Users) -> bool:
    return user.role is not None and user.role.name == ROLE_SUPER_ADMIN


def _is_platform_admin(user: Users) -> bool:
    return user.role is not None and user.role.name in {ROLE_SUPER_ADMIN, ROLE_ADMIN}


def _validate_role_assignment(db: Session, role_id: int, current_user: Users) -> None:
    role = crud_role.get_record_by_field(db, "id", role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )
    if role.scope != RoleScope.PLATFORM:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User accounts can only be assigned platform-scope roles",
        )
    if role.name == ROLE_SUPER_ADMIN and not _is_super_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a super_admin can assign the super_admin role",
        )


@router.post(
    "",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission(USER_CREATE))],
)
def create_user(
    payload: UserCreate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.role_id is not None:
        _validate_role_assignment(db, payload.role_id, current_user)
    user = crud_user.create_user(db, payload)
    return ResponseModel(data=user, message="User created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[UserOut]],
    dependencies=[Depends(require_permission(USERS_VIEW_ALL))],
)
def get_all_users(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    search: str | None = Query(None, max_length=100),
    role: str | None = Query(None, max_length=50),
    banned: bool | None = Query(None),
):
    users, total = crud_user.read_filtered(
        db,
        page=page,
        limit=limit,
        search=search,
        role=role,
        banned=banned,
    )
    return ResponseModel(
        success=True, data=users, total=total, message="Users retrieved successfully"
    )


@router.put("/me", response_model=ResponseModel[UserOut])
def update_my_profile(
    payload: UserProfileUpdate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    update_payload = payload
    if payload.avatar_url is not None:
        old_url = current_user.avatar_url
        update_payload = payload.model_copy(
            update={
                "avatar_url": validate_media_reference(
                    "avatar",
                    payload.avatar_url,
                    current_user.id,
                )
            }
        )
    else:
        old_url = None

    user = crud_user.update_user_profile(db, current_user.uid, update_payload)
    if old_url and old_url != user.avatar_url:
        path = extract_object_path(old_url)
        if path is not None:
            delete_object(path)
    return ResponseModel(data=user, message="Profile updated successfully")


@router.post(
    "/me/password",
    response_model=ResponseModel[PasswordChangeOut],
)
def change_my_password(
    payload: PasswordChangeIn,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = crud_user.change_password(db, current_user, payload)
    return ResponseModel(
        data=PasswordChangeOut(access_token=create_access_token(user.id)),
        message="Password changed successfully",
    )


@router.get(
    "/search",
    response_model=ResponseModel[list[UserBrief]],
)
def search_users(
    q: str = Query(..., min_length=3, max_length=100),
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    users = crud_user.search_active_users(db, query_text=q, limit=10)
    return ResponseModel(
        data=[UserBrief.model_validate(user) for user in users],
        total=len(users),
        message="Users retrieved successfully",
    )


@router.get(
    "/{uid}/profile",
    response_model=ResponseModel[UserPublicOut],
)
def get_user_profile(
    uid: UUID,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return ResponseModel(data=user, message="User profile retrieved successfully")


@router.post(
    "/{uid}/ban",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission(USER_BAN))],
)
def ban_user(
    uid: UUID,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot ban yourself",
        )
    if user.role is not None and user.role.name == ROLE_SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A super_admin cannot be banned",
        )
    if (
        user.role is not None
        and user.role.name == ROLE_ADMIN
        and not _is_super_admin(current_user)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a super_admin can ban an admin",
        )

    banned_user = crud_user.ban_user(db, user)
    return ResponseModel(data=banned_user, message="User banned successfully")


@router.post(
    "/{uid}/unban",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission(USER_UNBAN))],
)
def unban_user(
    uid: UUID,
    db: Session = Depends(get_db),
):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    unbanned_user = crud_user.unban_user(db, user)
    return ResponseModel(data=unbanned_user, message="User unbanned successfully")


@router.get(
    "/{uid}",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission(USER_VIEW_ONE))],
)
def get_user(
    uid: UUID,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if user.id != current_user.id and not _is_platform_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only view your own account or an account as an admin",
        )
    return ResponseModel(data=user, message="User retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[UserOut],
    dependencies=[Depends(require_permission(USER_UPDATE))],
)
def update_user(
    uid: UUID,
    payload: UserAdminUpdate,
    current_user: Users = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = crud_user.get_record_by_field(db, "uid", uid)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    is_super_admin = _is_super_admin(current_user)
    if not is_super_admin and user.role and user.role.name == "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a super_admin can modify a super_admin",
        )
    if payload.role_id is not None:
        _validate_role_assignment(db, payload.role_id, current_user)

    updated_user = crud_user.update_user(db, uid, payload)
    return ResponseModel(data=updated_user, message="User updated successfully")


# @router.delete(
#     "/{uid}",
#     response_model=ResponseModel[None],
#     dependencies=[Depends(require_permission("user.delete"))],
# )
# def delete_user(uid: UUID, db: Session = Depends(get_db)):
#     crud_user.delete_user(db, uid)
#     return ResponseModel(message="User deleted successfully")
