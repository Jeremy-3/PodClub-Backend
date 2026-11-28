from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.perm_names import USERS_VIEW_ALL
from app.crud.admin import read_admin_stats
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.admin import AdminStatsOut
from app.schema.response import ResponseModel


router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get(
    "/stats",
    response_model=ResponseModel[AdminStatsOut],
    dependencies=[Depends(require_permission(USERS_VIEW_ALL))],
)
def get_admin_stats(db: Session = Depends(get_db)):
    return ResponseModel(
        data=read_admin_stats(db),
        message="Admin statistics retrieved successfully",
    )
