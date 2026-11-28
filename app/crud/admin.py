from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.episodes import Episodes
from app.models.invites import Invites
from app.models.message import Messages
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.models.reports import ReportStatus, Reports
from app.models.users import Users
from app.schema.admin import AdminStatsOut


def read_admin_stats(db: Session) -> AdminStatsOut:
    statement = select(
        select(func.count(Users.id))
        .scalar_subquery()
        .label("users_total"),
        select(func.count(Users.id))
        .where(Users.is_active.is_(True))
        .scalar_subquery()
        .label("users_active"),
        select(func.count(Users.id))
        .where(Users.banned_at.is_not(None))
        .scalar_subquery()
        .label("users_banned"),
        select(func.count(PodClubs.id))
        .scalar_subquery()
        .label("podclubs_total"),
        select(func.count(PodClubs.id))
        .where(PodClubs.is_active.is_(True))
        .scalar_subquery()
        .label("podclubs_active"),
        select(func.count(PodClubs.id))
        .where(
            PodClubs.is_active.is_(True),
            PodClubs.is_private.is_(False),
        )
        .scalar_subquery()
        .label("podclubs_public"),
        select(func.count(PodClubMembers.id))
        .scalar_subquery()
        .label("memberships_total"),
        select(func.count(Podcasts.id))
        .scalar_subquery()
        .label("podcasts_total"),
        select(func.count(Episodes.id))
        .scalar_subquery()
        .label("episodes_total"),
        select(func.count(Messages.id))
        .scalar_subquery()
        .label("messages_total"),
        select(func.count(Reports.id))
        .scalar_subquery()
        .label("reports_total"),
        select(func.count(Reports.id))
        .where(Reports.status == ReportStatus.PENDING)
        .scalar_subquery()
        .label("reports_pending"),
        select(func.count(Invites.id))
        .scalar_subquery()
        .label("invites_total"),
    )
    row = db.execute(statement).one()
    return AdminStatsOut(**row._mapping)
