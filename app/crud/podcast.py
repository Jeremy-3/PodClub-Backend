from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podcasts import Podcasts
from app.schema.podcast import PodcastCreate, PodcastCreateDB, PodcastUpdate


MODEL = Podcasts


class CRUDPodcast(CRUDBase[MODEL, PodcastCreateDB]):
    """CRUD operations for Podcast model"""

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
