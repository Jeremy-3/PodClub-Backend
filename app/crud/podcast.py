from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.crud.base import CRUDBase
from app.models.episodes import Episodes
from app.models.podcasts import Podcasts
from app.schema.podcast import PodcastCreate, PodcastCreateDB, PodcastUpdate


MODEL = Podcasts


class CRUDPodcast(CRUDBase[MODEL, PodcastCreateDB]):
    """CRUD operations for Podcast model"""

    def read_for_clubs(
        self,
        db: Session,
        club_ids: set[int],
        podclub_id: int | None,
        page: int,
        limit: int,
    ) -> tuple[list[tuple[Podcasts, int]], int]:
        if not club_ids:
            return [], 0

        episode_count = (
            select(func.count(Episodes.id))
            .where(Episodes.podcast_id == MODEL.id)
            .correlate(MODEL)
            .scalar_subquery()
        )
        query = (
            db.query(MODEL, episode_count.label("episode_count"))
            .filter(MODEL.podclub_id.in_(club_ids))
        )
        if podclub_id is not None:
            query = query.filter(MODEL.podclub_id == podclub_id)

        total = query.with_entities(func.count(MODEL.id)).scalar()
        records = (
            query.options(
                joinedload(MODEL.creator),
                joinedload(MODEL.podclub),
            )
            .order_by(MODEL.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return [(podcast, count) for podcast, count in records], total

    def get_episode_count(self, db: Session, podcast_id: int) -> int:
        return (
            db.query(func.count(Episodes.id))
            .filter(Episodes.podcast_id == podcast_id)
            .scalar()
            or 0
        )

    def create_podcast(
        self, db: Session, record_create: PodcastCreate, creator_id: int
    ):
        db_obj = PodcastCreateDB(
            **record_create.model_dump(), creator_id=creator_id
        )
        return self.create(db, db_obj)

    def update_podcast(self, db: Session, uid: UUID, record_in: PodcastUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Podcast not found",
            )

        return self.update(db, record, record_in)

    def delete_podcast(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Podcast not found",
            )

        self.delete(db, record.id)


crud_podcast = CRUDPodcast(MODEL)
