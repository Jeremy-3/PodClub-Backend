from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podclubs import PodClubs
from app.schema.podclub import PodClubCreate, PodClubUpdate


MODEL = PodClubs


class CRUDPodClub(CRUDBase[MODEL, PodClubCreate]):
    """CRUD operations for PodClub model"""

    def create_podclub(self, db: Session, record_create: PodClubCreate):
        existing_record = self.get_record_by_field(db, "name", record_create.name)
        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PodClub name already exists",
            )

        return self.create(db, record_create)

    def update_podclub(self, db: Session, uid: UUID, record_in: PodClubUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )

        if record_in.name and record_in.name != record.name:
            existing_record = self.get_record_by_field(db, "name", record_in.name)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PodClub name already exists",
                )

        return self.update(db, record, record_in)

    def delete_podclub(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )

        self.delete(db, record.id)


crud_podclub = CRUDPodClub(MODEL)
