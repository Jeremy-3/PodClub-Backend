from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.message import Messages
from app.schema.message import MessageCreate, MessageCreateDB, MessageUpdate


MODEL = Messages


class CRUDMessage(CRUDBase[MODEL, MessageCreateDB]):
    """CRUD operations for Message model"""

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

        return self.update(db, record, record_in)

    def delete_message(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found",
            )

        self.delete(db, record.id)


crud_message = CRUDMessage(MODEL)
