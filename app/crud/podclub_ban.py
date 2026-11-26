from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podclub_bans import PodClubBans
from app.models.podclub_members import PodClubMembers
from app.schema.podclub_ban import PodClubBanCreateDB


MODEL = PodClubBans


class CRUDPodClubBan(CRUDBase[MODEL, PodClubBanCreateDB]):
    """CRUD operations for club bans."""

    def get_by_club_user(
        self, db: Session, podclub_id: int, user_id: int
    ) -> PodClubBans | None:
        return (
            db.query(MODEL)
            .filter(MODEL.podclub_id == podclub_id, MODEL.user_id == user_id)
            .first()
        )

    def list_for_club(self, db: Session, podclub_id: int) -> list[PodClubBans]:
        return (
            db.query(MODEL)
            .filter(MODEL.podclub_id == podclub_id)
            .order_by(MODEL.created_at.desc())
            .all()
        )

    def create_ban(
        self,
        db: Session,
        podclub_id: int,
        user_id: int,
        banned_by_id: int,
        reason: str | None,
    ) -> PodClubBans:
        if self.get_by_club_user(db, podclub_id, user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already banned from this PodClub",
            )

        membership = (
            db.query(PodClubMembers)
            .filter(
                PodClubMembers.podclub_id == podclub_id,
                PodClubMembers.user_id == user_id,
            )
            .first()
        )
        if membership is not None:
            db.delete(membership)

        record = PodClubBanCreateDB(
            podclub_id=podclub_id,
            user_id=user_id,
            banned_by_id=banned_by_id,
            reason=reason,
        )
        return self.create(db, record)

    def delete_ban(self, db: Session, record: PodClubBans) -> None:
        self.delete(db, record.id)


crud_podclub_ban = CRUDPodClubBan(MODEL)
