import secrets
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.invites import Invites
from app.schema.invite import InviteCreate, InviteCreateDB, InviteUpdate


MODEL = Invites


class CRUDInvite(CRUDBase[MODEL, InviteCreateDB]):
    """CRUD operations for Invite model"""

    def create_invite(
        self, db: Session, record_create: InviteCreate, invited_by_id: int
    ):
        record_data = record_create.model_dump()
        record_data.update(
            {
                "token": secrets.token_urlsafe(24),
                "invited_by_id": invited_by_id,
                "expires_at": record_create.expires_at
                or datetime.now(timezone.utc) + timedelta(days=2),
            }
        )
        db_obj = InviteCreateDB(**record_data)
        return self.create(db, db_obj)

    def update_invite(self, db: Session, uid: UUID, record_in: InviteUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        return self.update(db, record, record_in)

    def delete_invite(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        self.delete(db, record.id)


crud_invite = CRUDInvite(MODEL)
