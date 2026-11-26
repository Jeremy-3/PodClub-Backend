from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.episodes import Episodes
from app.models.podcasts import Podcasts
from app.schema.episode import EpisodeCreate, EpisodeCreateDB, EpisodeUpdate


MODEL = Episodes


class CRUDEpisode(CRUDBase[MODEL, EpisodeCreateDB]):
    """CRUD operations for Episode model"""

    def create_episode(
        self, db: Session, record_create: EpisodeCreate, created_by_id: int
    ):
        db_obj = EpisodeCreateDB(
            **record_create.model_dump(),
            created_by_id=created_by_id,
        )
        return self.create(db, db_obj)

    def read_for_clubs(
        self, db: Session, club_ids: set[int], page: int, limit: int
    ) -> tuple[list[Episodes], int]:
        if not club_ids:
            return [], 0

        query = (
            db.query(MODEL)
            .join(Podcasts, Podcasts.id == MODEL.podcast_id)
            .filter(Podcasts.podclub_id.in_(club_ids))
        )
        total = query.count()
        records = (
            query.order_by(MODEL.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return records, total

    def update_episode(self, db: Session, uid: UUID, record_in: EpisodeUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Episode not found",
            )

        return self.update(db, record, record_in)

    def delete_episode(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Episode not found",
            )

        self.delete(db, record.id)


crud_episode = CRUDEpisode(MODEL)
