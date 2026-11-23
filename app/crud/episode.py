from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.episodes import Episodes
from app.schema.episode import EpisodeCreate, EpisodeUpdate


MODEL = Episodes


class CRUDEpisode(CRUDBase[MODEL, EpisodeCreate]):
    """CRUD operations for Episode model"""

    def create_episode(self, db: Session, record_create: EpisodeCreate):
        return self.create(db, record_create)

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
