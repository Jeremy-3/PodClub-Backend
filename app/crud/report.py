from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.reports import ReportStatus, Reports
from app.schema.report import ReportCreate, ReportCreateDB, ReportUpdate


MODEL = Reports


class CRUDReport(CRUDBase[MODEL, ReportCreateDB]):
    """CRUD operations for Report model"""

    def create_report(
        self,
        db: Session,
        record_create: ReportCreate,
        reporter_id: int,
        podclub_id: int | None,
    ):
        record_data = record_create.model_dump()
        record_data["podclub_id"] = podclub_id
        db_obj = ReportCreateDB(
            **record_data,
            reporter_id=reporter_id,
            status=ReportStatus.PENDING,
        )
        return self.create(db, db_obj)

    def update_report(
        self, db: Session, uid: UUID, record_in: ReportUpdate, reviewed_by_id: int
    ):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found",
            )

        update_data = record_in.model_dump(exclude_unset=True)
        update_data["reviewed_by_id"] = reviewed_by_id
        return self.update(db, record, update_data)

    def delete_report(self, db: Session, uid: UUID):
        record = self.get_record_by_field(db, "uid", uid)
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found",
            )

        self.delete(db, record.id)


crud_report = CRUDReport(MODEL)
