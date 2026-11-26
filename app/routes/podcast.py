from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import PODCAST_CREATE, PODCAST_DELETE, PODCAST_UPDATE
from app.crud.podcast import crud_podcast
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.schema.podcast import PodcastCreate, PodcastOut, PodcastUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podcasts", tags=["Podcasts"])


def _get_visible_club(db: Session, access: Access, podclub_id: int) -> PodClubs:
    club = crud_podclub.get(db, podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PodClub not found",
        )
    return club


def _get_podcast(db: Session, uid: UUID) -> Podcasts:
    podcast = crud_podcast.get_record_by_field(db, "uid", uid)
    if podcast is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Podcast not found",
        )
    return podcast


def _get_podcast_club(db: Session, access: Access, podcast: Podcasts) -> PodClubs:
    if podcast.podclub_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Podcast not found",
        )
    return _get_visible_club(db, access, podcast.podclub_id)


@router.post("", response_model=ResponseModel[PodcastOut])
def create_podcast(
    payload: PodcastCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    club = _get_visible_club(db, access, payload.podclub_id)
    access.require(PODCAST_CREATE, club)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    podcast = crud_podcast.create_podcast(
        db, payload, creator_id=access.user.id
    )
    return ResponseModel(data=podcast, message="Podcast created successfully")


@router.get("", response_model=ResponseModel[list[PodcastOut]])
def get_all_podcasts(
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    podclub_id: int | None = Query(None, ge=1),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    if podclub_id is None:
        club_ids = access.visible_club_ids()
        filters = [{"field": "podclub_id", "op": "in", "value": club_ids}]
    else:
        _get_visible_club(db, access, podclub_id)
        filters = [{"field": "podclub_id", "value": podclub_id}]

    podcasts, total = crud_podcast.read(
        db,
        page=page,
        limit=limit,
        filters=filters,
    )
    return ResponseModel(
        data=podcasts,
        total=total,
        message="Podcasts retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[PodcastOut])
def get_podcast(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    podcast = _get_podcast(db, uid)
    _get_podcast_club(db, access, podcast)
    return ResponseModel(data=podcast, message="Podcast retrieved successfully")


@router.put("/{uid}", response_model=ResponseModel[PodcastOut])
def update_podcast(
    uid: UUID,
    payload: PodcastUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    podcast = _get_podcast(db, uid)
    club = _get_podcast_club(db, access, podcast)
    access.require(PODCAST_UPDATE, club)
    updated_podcast = crud_podcast.update_podcast(db, uid, payload)
    return ResponseModel(
        data=updated_podcast,
        message="Podcast updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
def delete_podcast(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    podcast = _get_podcast(db, uid)
    club = _get_podcast_club(db, access, podcast)
    access.require(PODCAST_DELETE, club)
    crud_podcast.delete_podcast(db, uid)
    return ResponseModel(message="Podcast deleted successfully")
