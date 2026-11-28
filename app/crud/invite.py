import secrets
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.crud.base import CRUDBase
from app.models.invites import Invites
from app.models.podclub_bans import PodClubBans
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.roles import RoleScope, Roles
from app.models.users import Users
from app.schema.invite import (
    InviteCreate,
    InviteCreateDB,
    InviteUpdate,
)


MODEL = Invites


class CRUDInvite(CRUDBase[MODEL, InviteCreateDB]):
    """CRUD operations for Invite model"""

    def get_by_token(self, db: Session, token: str) -> Invites | None:
        return (
            db.query(MODEL)
            .options(joinedload(MODEL.podclub))
            .filter(MODEL.token == token)
            .first()
        )

    def accept_invite(self, db: Session, token: str, user: Users) -> PodClubMembers:
        invite = (
            db.query(MODEL)
            .filter(MODEL.token == token)
            .with_for_update()
            .one_or_none()
        )
        if invite is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        now = datetime.now(timezone.utc)
        if invite.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Invite has expired",
            )
        if invite.max_uses > 0 and invite.use_count >= invite.max_uses:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Invite has no remaining uses",
            )
        if invite.email.strip().casefold() != user.email.strip().casefold():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invite email does not match the authenticated user",
            )

        club = db.query(PodClubs).filter(PodClubs.id == invite.podclub_id).one_or_none()
        if club is None or not club.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )

        if (
            db.query(PodClubBans.id)
            .filter(
                PodClubBans.podclub_id == club.id,
                PodClubBans.user_id == user.id,
            )
            .first()
            is not None
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is banned from this PodClub",
            )

        existing_member = (
            db.query(PodClubMembers.id)
            .filter(
                PodClubMembers.podclub_id == club.id,
                PodClubMembers.user_id == user.id,
            )
            .first()
        )
        if existing_member is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already a member of this PodClub",
            )

        role = (
            db.query(Roles)
            .filter(
                Roles.name == "club_member",
                Roles.scope == RoleScope.CLUB,
            )
            .one_or_none()
        )
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Club role 'club_member' not found; run the seed command",
            )

        member = PodClubMembers(
            podclub_id=club.id,
            user_id=user.id,
            role_id=role.id,
            user=user,
            role=role,
        )
        invite.use_count += 1
        if invite.accepted_at is None:
            invite.accepted_at = now
        db.add(member)

        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            existing_member = (
                db.query(PodClubMembers.id)
                .filter(
                    PodClubMembers.podclub_id == club.id,
                    PodClubMembers.user_id == user.id,
                )
                .first()
            )
            if existing_member is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User is already a member of this PodClub",
                ) from exc
            raise

        return (
            db.query(PodClubMembers)
            .options(
                joinedload(PodClubMembers.user),
                joinedload(PodClubMembers.role),
            )
            .filter(PodClubMembers.id == member.id)
            .one()
        )

    def create_invite(
        self, db: Session, record_create: InviteCreate, invited_by_id: int
    ):
        record_data = record_create.model_dump()
        record_data.update(
            {
                "token": secrets.token_urlsafe(24),
                "invited_by_id": invited_by_id,
                "expires_at": record_create.expires_at
                or datetime.now(timezone.utc) + timedelta(days=2),
            }
        )
        db_obj = InviteCreateDB(**record_data)
        return self.create(db, db_obj)

    def update_invite(self, db: Session, uid: UUID, record_in: InviteUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        return self.update(db, record, record_in)

    def delete_invite(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        self.delete(db, record.id)


crud_invite = CRUDInvite(MODEL)
