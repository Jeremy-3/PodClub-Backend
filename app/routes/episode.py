from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.perm_names import (
    EPISODE_CREATE,
    EPISODE_DELETE_ANY,
    EPISODE_DELETE_OWN,
    EPISODE_UPDATE_ANY,
    EPISODE_UPDATE_OWN,
)
from app.crud.episode import crud_episode
from app.crud.podcast import crud_podcast
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.models.episodes import Episodes
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.schema.episode import EpisodeCreate, EpisodeOut, EpisodeUpdate
from app.schema.response import ResponseModel
from app.services.media import validate_media_reference, delete_object
from app.services.websockets import connection_manager

router = APIRouter(prefix="/episodes", tags=["Episodes"])


def _get_episode(db: Session, uid: UUID) -> Episodes:
    episode = crud_episode.get_record_by_field(db, "uid", uid)
    if episode is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Episode not found",
        )
    return episode


def _get_episode_podcast(db: Session, episode: Episodes) -> Podcasts:
    podcast = crud_podcast.get(db, episode.podcast_id)
    if podcast is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Episode not found",
        )
    return podcast


def _get_episode_club(
    db: Session, access: Access, episode: Episodes
) -> PodClubs:
    podcast = _get_episode_podcast(db, episode)
    if podcast.podclub_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Episode not found",
        )
    club = crud_podclub.get(db, podcast.podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Episode not found",
        )
    return club


@router.post("", response_model=ResponseModel[EpisodeOut])
async def create_episode(
    payload: EpisodeCreate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    podcast = crud_podcast.get(db, payload.podcast_id)
    if podcast is None or podcast.podclub_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Podcast not found",
        )
    club = crud_podclub.get(db, podcast.podclub_id)
    if club is None or not access.club_visible(club):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Podcast not found",
        )
    access.require(EPISODE_CREATE, club)
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if payload.audio_url:
        payload = payload.model_copy(
            update={
                "audio_url": validate_media_reference(
                    "audio",
                    payload.audio_url,
                    access.user.id,
                    club.id,
                ),
                "duration": max(1, min(21600, payload.duration)),
            }
        )

    episode = crud_episode.create_episode(
        db,
        payload,
        created_by_id=access.user.id,
    )
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {
            "type": "episode.created",
            "data": EpisodeOut.model_validate(episode).model_dump(mode="json"),
        },
    )
    return ResponseModel(data=episode, message="Episode created successfully")


@router.get("", response_model=ResponseModel[list[EpisodeOut]])
def get_all_episodes(
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    podclub_id: int | None = Query(None, ge=1),
    podcast_id: int | None = Query(None, ge=1),
    search: str | None = Query(None, max_length=100),
    sort: Literal["newest"] = Query("newest"),
):
    visible_club_ids = access.visible_club_ids()
    if podclub_id is not None:
        club = crud_podclub.get(db, podclub_id)
        if club is None or not access.club_visible(club):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )
    episodes, total = crud_episode.read_for_clubs(
        db,
        club_ids=visible_club_ids,
        page=page,
        limit=limit,
        podclub_id=podclub_id,
        podcast_id=podcast_id,
        search=search,
    )
    return ResponseModel(
        data=episodes,
        total=total,
        message="Episodes retrieved successfully",
    )


@router.get("/{uid}", response_model=ResponseModel[EpisodeOut])
def get_episode(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    episode = _get_episode(db, uid)
    _get_episode_club(db, access, episode)
    return ResponseModel(data=episode, message="Episode retrieved successfully")


@router.put("/{uid}", response_model=ResponseModel[EpisodeOut])
async def update_episode(
    uid: UUID,
    payload: EpisodeUpdate,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    episode = _get_episode(db, uid)
    club = _get_episode_club(db, access, episode)
    if not access.can_own_or_any(
        EPISODE_UPDATE_OWN,
        EPISODE_UPDATE_ANY,
        club,
        episode.created_by_id,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Missing permission: {EPISODE_UPDATE_OWN} "
                f"or {EPISODE_UPDATE_ANY}"
            ),
        )

    update_payload = payload
    old_url = episode.audio_url
    if payload.audio_url is not None:
        update_payload = update_payload.model_copy(
            update={
                "audio_url": validate_media_reference(
                    "audio",
                    payload.audio_url,
                    episode.created_by_id or access.user.id,
                    club.id,
                )
            }
        )
    if payload.duration is not None:
        update_payload = update_payload.model_copy(
            update={"duration": max(1, min(21600, payload.duration))}
        )

    updated_episode = crud_episode.update_episode(db, uid, update_payload)
    if old_url and payload.audio_url is not None and old_url != updated_episode.audio_url:
        path = extract_object_path(old_url)
        if path is not None:
            delete_object(path)
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {
            "type": "episode.updated",
            "data": EpisodeOut.model_validate(updated_episode).model_dump(mode="json"),
        },
    )
    return ResponseModel(
        data=updated_episode,
        message="Episode updated successfully",
    )


@router.delete("/{uid}", response_model=ResponseModel[None])
async def delete_episode(
    uid: UUID,
    db: Session = Depends(get_db),
    access: Access = Depends(get_access),
):
    episode = _get_episode(db, uid)
    club = _get_episode_club(db, access, episode)
    if not access.can_own_or_any(
        EPISODE_DELETE_OWN,
        EPISODE_DELETE_ANY,
        club,
        episode.created_by_id,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Missing permission: {EPISODE_DELETE_OWN} "
                f"or {EPISODE_DELETE_ANY}"
            ),
        )

    audio_url = episode.audio_url
    crud_episode.delete_episode(db, uid)
    from app.services.media import extract_object_path

    path = extract_object_path(audio_url)
    if path is not None:
        delete_object(path)
    await connection_manager.broadcast(
        f"podclub:{club.id}",
        {"type": "episode.deleted", "data": {"id": episode.id, "uid": str(episode.uid)}},
    )
    return ResponseModel(message="Episode deleted successfully")
