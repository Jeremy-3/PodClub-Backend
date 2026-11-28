from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased, selectinload

from app.crud.base import CRUDBase
from app.models.message import Messages
from app.schema.message import MessageCreate, MessageCreateDB, MessageUpdate


MODEL = Messages


class CRUDMessage(CRUDBase[MODEL, MessageCreateDB]):
    """CRUD operations for Message model"""

    def read_for_club(
        self,
        db: Session,
        podclub_id: int,
        page: int,
        limit: int,
        after_id: int | None = None,
        before_id: int | None = None,
    ) -> tuple[list[tuple[Messages, int]], int]:
        reply = aliased(MODEL)
        reply_count = (
            select(func.count(reply.id))
            .where(reply.parent_message_id == MODEL.id)
            .correlate(MODEL)
            .scalar_subquery()
        )
        query = db.query(MODEL, reply_count.label("reply_count")).filter(
            MODEL.podclub_id == podclub_id
        )
        count_query = db.query(func.count(MODEL.id)).filter(
            MODEL.podclub_id == podclub_id
        )
        if after_id is not None:
            query = query.filter(MODEL.id > after_id)
        if before_id is not None:
            query = query.filter(MODEL.id < before_id)

        total = count_query.scalar()
        query = query.options(
            selectinload(MODEL.sender),
            selectinload(MODEL.parent_message).joinedload(Messages.sender),
        )
        if before_id is not None:
            query = query.order_by(MODEL.id.desc())
        else:
            query = query.order_by(MODEL.id.asc())
        if after_id is None and before_id is None:
            query = query.offset((page - 1) * limit)

        records = query.limit(limit).all()
        if before_id is not None:
            records.reverse()
        return [(message, count) for message, count in records], total

    def get_with_reply_count(
        self, db: Session, uid: UUID
    ) -> tuple[Messages, int] | None:
        reply = aliased(MODEL)
        reply_count = (
            select(func.count(reply.id))
            .where(reply.parent_message_id == MODEL.id)
            .correlate(MODEL)
            .scalar_subquery()
        )
        return (
            db.query(MODEL, reply_count.label("reply_count"))
            .options(
                selectinload(MODEL.sender),
                selectinload(MODEL.parent_message).joinedload(Messages.sender),
            )
            .filter(MODEL.uid == uid)
            .first()
        )

    def create_message(
        self, db: Session, record_create: MessageCreate, sender_id: int
    ):
        db_obj = MessageCreateDB(**record_create.model_dump(), sender_id=sender_id)
        return self.create(db, db_obj)

    def update_message(self, db: Session, uid: UUID, record_in: MessageUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found",
            )
        if record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Deleted messages cannot be edited",
            )

        update_data = record_in.model_dump(exclude_unset=True)
        update_data["is_edited"] = True
        return self.update(db, record, update_data)

    def delete_message(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found",
            )

        if not record.is_deleted:
            return self.update(db, record, {"is_deleted": True})
        return record


crud_message = CRUDMessage(MODEL)
