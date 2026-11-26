from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import (
    REPORT_CREATE,
    REPORT_DELETE,
    REPORT_REVIEW_CLUB,
    REPORT_UPDATE,
    REPORT_VIEW_ONE,
    REPORTS_VIEW_ALL,
)
from app.crud.message import crud_message
from app.crud.podclub import crud_podclub
from app.crud.report import crud_report
from app.crud.user import crud_user
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.podclubs import PodClubs
from app.models.reports import Reports
from app.schema.report import ReportCreate, ReportOut, ReportUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/reports", tags=["Reports"])


def _get_visible_club(db: Session, access: Access, podclub_id: int) -> PodClubs:
    club = crud_podclub.get(db, podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _get_report(db: Session, uid: UUID) -> Reports:
    report = crud_report.get_record_by_field(db, "uid", uid)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return report


def _require_report_review_access(
    db: Session,
    access: Access,
    report: Reports,
    platform_permission: str,
) -> None:
    if access.can(platform_permission):
        return
    if report.podclub_id is None:
        access.require(platform_permission)
    club = _get_visible_club(db, access, report.podclub_id)
    access.require(REPORT_REVIEW_CLUB, club)


@router.post("", response_model=ResponseModel[ReportOut])
def create_report(
    payload: ReportCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    access.require(REPORT_CREATE)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if payload.reported_user_id is not None:
        if payload.reported_user_id == access.user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot report yourself",
            )
        if crud_user.get(db, payload.reported_user_id) is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reported user not found",
            )

    report_podclub_id = None
    if payload.message_id is not None:
        message = crud_message.get(db, payload.message_id)
        if message is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found",
            )
        club = _get_visible_club(db, access, message.podclub_id)
        report_podclub_id = club.id
    elif payload.podclub_id is not None:
        club = _get_visible_club(db, access, payload.podclub_id)
        if access.club_role(club) is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You must be a member of this PodClub to report it",
            )
        report_podclub_id = club.id

    report = crud_report.create_report(
        db,
        payload,
        reporter_id=access.user.id,
        podclub_id=report_podclub_id,
    )
    return ResponseModel(data=report, message="Report created successfully")


@router.get("", response_model=ResponseModel[list[ReportOut]])
def get_all_reports(
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    podclub_id: int | None = Query(None, ge=1),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    filters = []
    if access.can(REPORTS_VIEW_ALL):
        if podclub_id is not None:
            filters.append({"field": "podclub_id", "value": podclub_id})
    else:
        if podclub_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="podclub_id is required to list club reports",
            )
        club = _get_visible_club(db, access, podclub_id)
        access.require(REPORT_REVIEW_CLUB, club)
        filters.append({"field": "podclub_id", "value": club.id})

    reports, total = crud_report.read(
        db,
        page=page,
        limit=limit,
        filters=filters,
    )
    return ResponseModel(
        data=reports,
        total=total,
        message="Reports retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[ReportOut])
def get_report(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    report = _get_report(db, uid)
    _require_report_review_access(db, access, report, REPORT_VIEW_ONE)
    return ResponseModel(data=report, message="Report retrieved successfully")


@router.put("/{uid}", response_model=ResponseModel[ReportOut])
def update_report(
    uid: UUID,
    payload: ReportUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    report = _get_report(db, uid)
    _require_report_review_access(db, access, report, REPORT_UPDATE)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    updated_report = crud_report.update_report(
        db,
        uid,
        payload,
        reviewed_by_id=access.user.id,
    )
    return ResponseModel(
        data=updated_report,
        message="Report updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_report(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    access.require(REPORT_DELETE)
    crud_report.delete_report(db, uid)
    return ResponseModel(message="Report deleted successfully")
