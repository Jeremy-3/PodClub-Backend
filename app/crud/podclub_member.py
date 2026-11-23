from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podclub_members import PodClubMembers
from app.schema.podclub_member import PodClubMemberCreate, PodClubMemberUpdate


MODEL = PodClubMembers


class CRUDPodClubMember(CRUDBase[MODEL, PodClubMemberCreate]):
    """CRUD operations for PodClubMember model"""

    def create_podclub_member(self, db: Session, record_create: PodClubMemberCreate):
        existing_record = self.get_record_by_fields(
            db,
            {
                "podclub_id": record_create.podclub_id,
                "user_id": record_create.user_id,
            },
        )
        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PodClub member already exists",
            )

        return self.create(db, record_create)

    def update_podclub_member(
        self, db: Session, uid: UUID, record_in: PodClubMemberUpdate
    ):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub member not found",
            )

        update_data = record_in.model_dump(exclude_unset=True)
        podclub_id = update_data.get("podclub_id", record.podclub_id)
        user_id = update_data.get("user_id", record.user_id)
        if podclub_id != record.podclub_id or user_id != record.user_id:
            existing_record = self.get_record_by_fields(
                db, {"podclub_id": podclub_id, "user_id": user_id}
            )
            if existing_record and existing_record.id != record.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PodClub member already exists",
                )

        return self.update(db, record, record_in)

    def delete_podclub_member(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub member not found",
            )

        self.delete(db, record.id)


crud_podclub_member = CRUDPodClubMember(MODEL)
