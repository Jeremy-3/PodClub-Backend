from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.schema.podclub import PodClubCreate, PodClubCreateDB, PodClubUpdate


MODEL = PodClubs


class CRUDPodClub(CRUDBase[MODEL, PodClubCreateDB]):
    """CRUD operations for PodClub model"""

    def read_for_user(
        self,
        db: Session,
        user_id: int | None,
        can_read_private: bool,
        page: int,
        limit: int,
    ) -> tuple[list[PodClubs], int]:
        query = db.query(MODEL)
        if not can_read_private:
            visible_clauses = [
                and_(
                    MODEL.is_active.is_(True),
                    MODEL.is_private.is_(False),
                )
            ]
            if user_id is not None:
                visible_clauses.extend(
                    [
                        MODEL.owner_id == user_id,
                        MODEL.id.in_(
                            select(PodClubMembers.podclub_id).where(
                                PodClubMembers.user_id == user_id
                            )
                        ),
                    ]
                )
            query = query.filter(or_(*visible_clauses))

        total = query.count()
        records = (
            query.order_by(MODEL.created_at.desc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return records, total

    def create_podclub(
        self, db: Session, record_create: PodClubCreate, owner_id: int
    ):
        existing_record = self.get_record_by_field(db, "name", record_create.name)
        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PodClub name already exists",
            )

        db_obj = PodClubCreateDB(**record_create.model_dump(), owner_id=owner_id)
        return self.create(db, db_obj)

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
