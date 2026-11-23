from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.episode import crud_episode
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.episode import EpisodeCreate, EpisodeOut, EpisodeUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/episodes", tags=["Episodes"])


@router.post(
    "",
    response_model=ResponseModel[EpisodeOut],
    dependencies=[Depends(require_permission("episode.create"))],
)
def create_episode(payload: EpisodeCreate, db: Session = Depends(get_db)):
    episode = crud_episode.create_episode(db, payload)
    return ResponseModel(data=episode, message="Episode created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[EpisodeOut]],
    dependencies=[Depends(require_permission("episodes.view_all"))],
)
def get_all_episodes(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    episodes, total = crud_episode.read(db, page=page, limit=limit)
    return ResponseModel(
        data=episodes, total=total, message="Episodes retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[EpisodeOut],
    dependencies=[Depends(require_permission("episode.view_one"))],
)
def get_episode(uid: UUID, db: Session = Depends(get_db)):
    episode = crud_episode.get_record_by_field(db, "uid", uid)
    if not episode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Episode not found"
        )
    return ResponseModel(data=episode, message="Episode retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[EpisodeOut],
    dependencies=[Depends(require_permission("episode.update"))],
)
def update_episode(uid: UUID, payload: EpisodeUpdate, db: Session = Depends(get_db)):
    episode = crud_episode.update_episode(db, uid, payload)
    return ResponseModel(data=episode, message="Episode updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("episode.delete"))],
)
def delete_episode(uid: UUID, db: Session = Depends(get_db)):
    crud_episode.delete_episode(db, uid)
    return ResponseModel(message="Episode deleted successfully")
