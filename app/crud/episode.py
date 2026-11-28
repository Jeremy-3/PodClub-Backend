from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, joinedload, selectinload

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
        self,
        db: Session,
        club_ids: set[int],
        page: int,
        limit: int,
        podclub_id: int | None = None,
        podcast_id: int | None = None,
        search: str | None = None,
    ) -> tuple[list[Episodes], int]:
        if not club_ids:
            return [], 0

        query = (
            db.query(MODEL)
            .join(Podcasts, Podcasts.id == MODEL.podcast_id)
            .filter(Podcasts.podclub_id.in_(club_ids))
        )
        if podclub_id is not None:
            query = query.filter(Podcasts.podclub_id == podclub_id)
        if podcast_id is not None:
            query = query.filter(MODEL.podcast_id == podcast_id)
        if search:
            query = query.filter(
                or_(
                    MODEL.title.ilike(f"%{search}%"),
                    MODEL.description.ilike(f"%{search}%"),
                )
            )
        total = query.with_entities(func.count(MODEL.id)).scalar()
        records = (
            query.options(
                selectinload(MODEL.created_by),
                joinedload(MODEL.podcast).joinedload(Podcasts.podclub),
            )
            .order_by(MODEL.created_at.desc())
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
