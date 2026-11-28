from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import settings
from app.core.perm_names import (
    CLUB_UPDATE,
    EPISODE_CREATE,
    MESSAGE_CREATE,
)
from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.access import Access, get_access
from app.schema.response import ResponseModel
from app.schema.upload import UploadSignIn, UploadSignOut
from app.services import media


router = APIRouter(prefix="/uploads", tags=["Uploads"])


@router.post("/sign", response_model=ResponseModel[UploadSignOut])
def sign_upload(
    payload: UploadSignIn,
    db=Depends(get_db),
    access: Access = Depends(get_access),
):
    media.require_storage()
    if access.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if payload.kind in {"audio", "image"}:
        if payload.podclub_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="podclub_id is required for this upload kind",
            )
        club = crud_podclub.get(db, payload.podclub_id)
        if club is None or not access.club_visible(club):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )
        permission = (
            EPISODE_CREATE if payload.kind == "audio" else MESSAGE_CREATE
        )
        access.require(permission, club)
    elif payload.kind == "club_cover":
        if payload.podclub_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="podclub_id is required for this upload kind",
            )
        club = crud_podclub.get(db, payload.podclub_id)
        if club is None or not access.club_visible(club):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="PodClub not found",
            )
        access.require(CLUB_UPDATE, club)
    elif payload.kind == "avatar":
        pass

    extension = media.validate_extension_and_mime(
        payload.kind,
        payload.filename,
        payload.content_type,
    )
    path = media.build_object_path(
        payload.kind,
        access.user.id,
        extension,
        payload.podclub_id,
    )
    signed = media.create_signed_upload_url(path)
    max_mb = (
        settings.MAX_AUDIO_MB
        if payload.kind == "audio"
        else settings.MAX_IMAGE_MB
    )
    return ResponseModel(
        data=UploadSignOut(
            signed_url=signed["signed_url"],
            token=signed["token"],
            path=path,
            public_url=signed["public_url"],
            expires_in=3600,
            bucket=settings.SUPABASE_STORAGE_BUCKET,
            max_bytes=max_mb * 1024 * 1024,
        ),
        message="Signed upload URL created successfully",
    )
