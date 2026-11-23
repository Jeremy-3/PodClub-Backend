from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.podcast import crud_podcast
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.podcast import PodcastCreate, PodcastOut, PodcastUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podcasts", tags=["Podcasts"])


@router.post(
    "",
    response_model=ResponseModel[PodcastOut],
    dependencies=[Depends(require_permission("podcast.create"))],
)
def create_podcast(payload: PodcastCreate, db: Session = Depends(get_db)):
    podcast = crud_podcast.create_podcast(db, payload)
    return ResponseModel(data=podcast, message="Podcast created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[PodcastOut]],
    dependencies=[Depends(require_permission("podcasts.view_all"))],
)
def get_all_podcasts(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    podcasts, total = crud_podcast.read(db, page=page, limit=limit)
    return ResponseModel(
        data=podcasts, total=total, message="Podcasts retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[PodcastOut],
    dependencies=[Depends(require_permission("podcast.view_one"))],
)
def get_podcast(uid: UUID, db: Session = Depends(get_db)):
    podcast = crud_podcast.get_record_by_field(db, "uid", uid)
    if not podcast:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Podcast not found"
        )
    return ResponseModel(data=podcast, message="Podcast retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[PodcastOut],
    dependencies=[Depends(require_permission("podcast.update"))],
)
def update_podcast(uid: UUID, payload: PodcastUpdate, db: Session = Depends(get_db)):
    podcast = crud_podcast.update_podcast(db, uid, payload)
    return ResponseModel(data=podcast, message="Podcast updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("podcast.delete"))],
)
def delete_podcast(uid: UUID, db: Session = Depends(get_db)):
    crud_podcast.delete_podcast(db, uid)
    return ResponseModel(message="Podcast deleted successfully")
