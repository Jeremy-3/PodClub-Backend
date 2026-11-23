from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.report import crud_report
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.report import ReportCreate, ReportOut, ReportUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "",
    response_model=ResponseModel[ReportOut],
    dependencies=[Depends(require_permission("report.create"))],
)
def create_report(payload: ReportCreate, db: Session = Depends(get_db)):
    report = crud_report.create_report(db, payload)
    return ResponseModel(data=report, message="Report created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[ReportOut]],
    dependencies=[Depends(require_permission("reports.view_all"))],
)
def get_all_reports(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    reports, total = crud_report.read(db, page=page, limit=limit)
    return ResponseModel(
        data=reports, total=total, message="Reports retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[ReportOut],
    dependencies=[Depends(require_permission("report.view_one"))],
)
def get_report(uid: UUID, db: Session = Depends(get_db)):
    report = crud_report.get_record_by_field(db, "uid", uid)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Report not found"
        )
    return ResponseModel(data=report, message="Report retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[ReportOut],
    dependencies=[Depends(require_permission("report.update"))],
)
def update_report(uid: UUID, payload: ReportUpdate, db: Session = Depends(get_db)):
    report = crud_report.update_report(db, uid, payload)
    return ResponseModel(data=report, message="Report updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("report.delete"))],
)
def delete_report(uid: UUID, db: Session = Depends(get_db)):
    crud_report.delete_report(db, uid)
    return ResponseModel(message="Report deleted successfully")
