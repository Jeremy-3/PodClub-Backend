from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.podclub_members import PodClubMembers
from app.schema.podclub_member import PodClubMemberCreate, PodClubMemberCreateDB


MODEL = PodClubMembers


class CRUDPodClubMember(CRUDBase[MODEL, PodClubMemberCreate]):
    """CRUD operations for PodClubMember model"""

    def get_by_club_user(
        self, db: Session, podclub_id: int, user_id: int
    ) -> PodClubMembers | None:
        return (
            db.query(MODEL)
            .filter(MODEL.podclub_id == podclub_id, MODEL.user_id == user_id)
            .first()
        )

    def create_podclub_member(
        self,
        db: Session,
        record_create: PodClubMemberCreate,
        role_id: int,
    ) -> PodClubMembers:
        if self.get_by_club_user(db, record_create.podclub_id, record_create.user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PodClub member already exists",
            )

        db_obj = PodClubMemberCreateDB(
            **record_create.model_dump(),
            role_id=role_id,
        )
        return self.create(db, db_obj)

    def update_podclub_member_role(
        self, db: Session, record: PodClubMembers, role_id: int
    ) -> PodClubMembers:
        return self.update(db, record, {"role_id": role_id})

    def delete_podclub_member(self, db: Session, record: PodClubMembers) -> None:
        self.delete(db, record.id)


crud_podclub_member = CRUDPodClubMember(MODEL)
