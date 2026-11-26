from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.dependencies.auth import get_optional_current_user
from app.models.permissions import Permissions
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.role_permissions import RolePermission
from app.models.roles import RoleScope, Roles
from app.models.users import Users


class Access:
    def __init__(self, db: Session, user: Users | None) -> None:
        self.db = db
        self.user = user
        self._platform_perms: frozenset[str] | None = None
        self._club_roles: dict[int, Roles | None] = {}
        self._club_perms: dict[int, frozenset[str]] = {}
        self._role_perms: dict[int, frozenset[str]] = {}
        self._club_owner_role_loaded = False
        self._club_owner_role: Roles | None = None
        self._visible_club_ids: frozenset[int] | None = None

    @property
    def platform_perms(self) -> set[str]:
        if self._platform_perms is None:
            role = self.user.role if self.user is not None else None
            if (
                role is None
                or not role.active
                or role.scope != RoleScope.PLATFORM
            ):
                self._platform_perms = frozenset()
            else:
                self._platform_perms = self._permissions_for_role(role)
        return set(self._platform_perms)

    def club_role(self, club: PodClubs) -> Roles | None:
        club_id = club.id
        if club_id in self._club_roles:
            return self._club_roles[club_id]

        if self.user is None:
            role = None
        elif club.owner_id == self.user.id:
            if not self._club_owner_role_loaded:
                self._club_owner_role = (
                    self.db.query(Roles)
                    .filter(
                        Roles.name == "club_owner",
                        Roles.scope == RoleScope.CLUB,
                    )
                    .one_or_none()
                )
                self._club_owner_role_loaded = True
            role = self._club_owner_role
        else:
            role = (
                self.db.query(Roles)
                .join(PodClubMembers, PodClubMembers.role_id == Roles.id)
                .filter(
                    PodClubMembers.podclub_id == club_id,
                    PodClubMembers.user_id == self.user.id,
                )
                .one_or_none()
            )
            if role is not None and role.scope != RoleScope.CLUB:
                role = None

        self._club_roles[club_id] = role
        return role

    def club_perms(self, club: PodClubs) -> set[str]:
        club_id = club.id
        if club_id not in self._club_perms:
            role = self.club_role(club)
            if role is None or not role.active or role.scope != RoleScope.CLUB:
                permissions = frozenset()
            else:
                permissions = self._permissions_for_role(role)
            self._club_perms[club_id] = permissions
        return set(self._club_perms[club_id])

    def can(self, perm: str, club: PodClubs | None = None) -> bool:
        if self.user is None:
            return False

        role = self.user.role
        if (
            role is not None
            and role.active
            and role.scope == RoleScope.PLATFORM
            and role.name == "super_admin"
        ):
            return True

        if perm in self.platform_perms:
            return True
        return club is not None and perm in self.club_perms(club)

    def require(
        self,
        perm: str,
        club: PodClubs | None = None,
        not_found: bool = False,
    ) -> bool:
        if self.can(perm, club):
            return True
        raise HTTPException(
            status_code=(
                status.HTTP_404_NOT_FOUND if not_found else status.HTTP_403_FORBIDDEN
            ),
            detail=f"Missing permission: {perm}",
        )

    def can_own_or_any(
        self,
        own_perm: str,
        any_perm: str,
        club: PodClubs,
        author_id: int | None,
    ) -> bool:
        if self.user is None:
            return False
        if author_id == self.user.id and self.can(own_perm, club):
            return True
        return self.can(any_perm, club)

    def club_visible(self, club: PodClubs) -> bool:
        if club.is_active and not club.is_private:
            return True
        return self.can("club.read_private", club)

    def visible_club_ids(self) -> set[int]:
        if self._visible_club_ids is None:
            clubs = self.db.query(PodClubs).all()
            self._visible_club_ids = frozenset(
                club.id for club in clubs if self.club_visible(club)
            )
        return set(self._visible_club_ids)

    def _permissions_for_role(self, role: Roles) -> frozenset[str]:
        if role.id not in self._role_perms:
            rows = (
                self.db.query(Permissions.name)
                .join(
                    RolePermission,
                    RolePermission.permission_id == Permissions.id,
                )
                .filter(RolePermission.role_id == role.id)
                .all()
            )
            self._role_perms[role.id] = frozenset(name for (name,) in rows)
        return self._role_perms[role.id]


def get_access(
    db: Session = Depends(get_db),
    user: Users | None = Depends(get_optional_current_user),
) -> Access:
    return Access(db=db, user=user)
