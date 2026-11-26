import secrets
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.invites import Invites
from app.schema.invite import InviteCreate, InviteUpdate


MODEL = Invites


class CRUDInvite(CRUDBase[MODEL, InviteCreate]):
    """CRUD operations for Invite model"""

    def create_invite(self, db: Session, record_create: InviteCreate):
        if not record_create.token:
            record_create.token = secrets.token_urlsafe(24)
        else:
            existing_record = self.get_record_by_field(db, "token", record_create.token)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invite token already exists",
                )

        if not record_create.expires_at:
            record_create.expires_at = datetime.now(timezone.utc) + timedelta(days=2)

        return self.create(db, record_create)

    def update_invite(self, db: Session, uid: UUID, record_in: InviteUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invite not found",
            )

        if record_in.token and record_in.token != record.token:
            existing_record = self.get_record_by_field(db, "token", record_in.token)
            if existing_record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invite token already exists",
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
