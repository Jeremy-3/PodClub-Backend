from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import and_, case, func, literal, or_, select
from sqlalchemy.orm import Session, joinedload

from app.crud.base import CRUDBase
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.roles import RoleScope, Roles
from app.models.users import Users
from app.schema.podclub import PodClubCreate, PodClubCreateDB, PodClubUpdate


MODEL = PodClubs
MAX_OWNED_PODCLUBS = 5


class CRUDPodClub(CRUDBase[MODEL, PodClubCreateDB]):
    """CRUD operations for PodClub model"""

    def read_for_user(
        self,
        db: Session,
        user_id: int | None,
        can_read_private: bool,
        page: int,
        limit: int,
        mine: bool = False,
        search: str | None = None,
        sort: str = "newest",
    ) -> tuple[list[tuple[PodClubs, int, str | None]], int]:
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

        if mine and user_id is not None:
            query = query.filter(
                or_(
                    MODEL.owner_id == user_id,
                    MODEL.id.in_(
                        select(PodClubMembers.podclub_id).where(
                            PodClubMembers.user_id == user_id
                        )
                    ),
                )
            )
        if search:
            query = query.filter(
                or_(
                    MODEL.name.ilike(f"%{search}%"),
                    MODEL.description.ilike(f"%{search}%"),
                )
            )

        member_count = (
            select(func.count(PodClubMembers.id))
            .where(PodClubMembers.podclub_id == MODEL.id)
            .correlate(MODEL)
            .scalar_subquery()
        )
        if user_id is not None:
            query = (
                query.outerjoin(
                    PodClubMembers,
                    and_(
                        PodClubMembers.podclub_id == MODEL.id,
                        PodClubMembers.user_id == user_id,
                    ),
                )
                .outerjoin(Roles, Roles.id == PodClubMembers.role_id)
            )
            my_role = case(
                (MODEL.owner_id == user_id, "club_owner"),
                (Roles.scope == RoleScope.CLUB, Roles.name),
                else_=None,
            )
        else:
            my_role = literal(None)

        total = query.with_entities(func.count(func.distinct(MODEL.id))).scalar()
        ordering = (
            func.lower(MODEL.name).asc()
            if sort == "name"
            else MODEL.created_at.desc()
        )
        records = (
            query.with_entities(MODEL, member_count, my_role)
            .options(joinedload(MODEL.owner))
            .order_by(ordering, MODEL.id.asc())
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )
        return [(club, count, role) for club, count, role in records], total

    def get_member_count(self, db: Session, podclub_id: int) -> int:
        return (
            db.query(func.count(PodClubMembers.id))
            .filter(PodClubMembers.podclub_id == podclub_id)
            .scalar()
            or 0
        )

    def create_podclub(
        self, db: Session, record_create: PodClubCreate, owner_id: int
    ):
        existing_record = self.get_record_by_field(db, "name", record_create.name)
        if existing_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="PodClub name already exists",
            )

        owner = (
            db.query(Users)
            .filter(Users.id == owner_id)
            .with_for_update()
            .one_or_none()
        )
        if owner is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        owned_count = (
            db.query(func.count(MODEL.id))
            .filter(MODEL.owner_id == owner_id)
            .scalar()
        )
        if owned_count >= MAX_OWNED_PODCLUBS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user may own at most 5 PodClubs",
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
