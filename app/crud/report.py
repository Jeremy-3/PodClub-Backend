from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.reports import Reports
from app.schema.report import ReportCreate, ReportUpdate


MODEL = Reports


class CRUDReport(CRUDBase[MODEL, ReportCreate]):
    """CRUD operations for Report model"""

    def create_report(self, db: Session, record_create: ReportCreate):
        return self.create(db, record_create)

    def update_report(self, db: Session, uid: UUID, record_in: ReportUpdate):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found",
            )

        return self.update(db, record, record_in)

    def delete_report(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found",
            )

        self.delete(db, record.id)


crud_report = CRUDReport(MODEL)
