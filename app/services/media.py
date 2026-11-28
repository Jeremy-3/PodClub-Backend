import mimetypes
import uuid
from pathlib import Path

import httpx
from fastapi import HTTPException, status

from app.core.config import settings


ALLOWED_AUDIO_MIME_TYPES = {
    "audio/mpeg",
    "audio/mp4",
    "audio/x-m4a",
    "audio/wav",
    "audio/ogg",
}
ALLOWED_IMAGE_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}
MIME_BY_EXTENSION = {
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}


def is_configured() -> bool:
    return bool(settings.SUPABASE_URL and settings.SUPABASE_SERVICE_ROLE_KEY)


def require_storage() -> None:
    if not is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase Storage is not configured",
        )


def _headers() -> dict[str, str]:
    require_storage()
    return {
        "Authorization": f"Bearer {settings.SUPABASE_SERVICE_ROLE_KEY}",
        "apikey": settings.SUPABASE_SERVICE_ROLE_KEY,
    }


def _storage_url() -> str:
    return settings.SUPABASE_URL.rstrip("/") + "/storage/v1"


def create_signed_upload_url(path: str) -> dict:
    require_storage()
    signed_url = f"{_storage_url()}/object/upload/sign/{settings.SUPABASE_STORAGE_BUCKET}/{path}"
    response = httpx.post(
        signed_url,
        headers=_headers(),
        json={},
        timeout=30,
    )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not create Supabase signed upload URL",
        )
    data = response.json()
    token = data.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Supabase did not return an upload token",
        )
    public_url = (
        f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/public/"
        f"{settings.SUPABASE_STORAGE_BUCKET}/{path}"
    )
    return {
        "signed_url": f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1"
        f"/object/upload/sign/{settings.SUPABASE_STORAGE_BUCKET}/{path}?token={token}",
        "token": token,
        "public_url": public_url,
    }


def setup_bucket() -> str:
    if not is_configured():
        raise RuntimeError(
            "Supabase Storage is not configured; set SUPABASE_URL and "
            "SUPABASE_SERVICE_ROLE_KEY"
        )
    headers = _headers()
    bucket_url = f"{_storage_url()}/bucket"
    file_size_limit = settings.MAX_AUDIO_MB * 1024 * 1024
    options = {
        "public": True,
        "file_size_limit": file_size_limit,
        "allowed_mime_types": sorted(
            ALLOWED_AUDIO_MIME_TYPES | ALLOWED_IMAGE_MIME_TYPES
        ),
    }

    response = httpx.get(
        f"{bucket_url}/{settings.SUPABASE_STORAGE_BUCKET}",
        headers=headers,
        timeout=30,
    )
    if response.status_code == 404:
        response = httpx.post(
            bucket_url,
            headers=headers,
            json={"id": settings.SUPABASE_STORAGE_BUCKET, "name": settings.SUPABASE_STORAGE_BUCKET, **options},
            timeout=30,
        )
    elif response.status_code >= 400:
        raise RuntimeError(f"Could not inspect Supabase bucket: {response.status_code}")
    else:
        response = httpx.put(
            f"{bucket_url}/{settings.SUPABASE_STORAGE_BUCKET}",
            headers=headers,
            json=options,
            timeout=30,
        )

    if response.status_code >= 400:
        raise RuntimeError(f"Could not configure Supabase bucket: {response.status_code}")
    return settings.SUPABASE_STORAGE_BUCKET


def delete_object(path: str) -> bool:
    if not is_configured():
        return False
    try:
        response = httpx.delete(
            f"{_storage_url()}/object/{settings.SUPABASE_STORAGE_BUCKET}",
            headers=_headers(),
            json={"prefixes": [path]},
            timeout=15,
        )
        return response.status_code < 400
    except Exception:
        return False


def validate_extension_and_mime(kind: str, filename: str, content_type: str) -> str:
    extension = Path(filename).suffix.lower()
    expected = {
        "audio": ALLOWED_AUDIO_MIME_TYPES,
        "image": ALLOWED_IMAGE_MIME_TYPES,
        "club_cover": ALLOWED_IMAGE_MIME_TYPES,
        "avatar": ALLOWED_IMAGE_MIME_TYPES,
    }[kind]
    if extension not in MIME_BY_EXTENSION:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file extension",
        )
    if MIME_BY_EXTENSION[extension] not in expected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File extension is not allowed for this upload kind",
        )
    if content_type not in expected or content_type != MIME_BY_EXTENSION[extension]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Content type is not allowed for this upload kind",
        )
    return extension.lstrip(".")


def build_object_path(
    kind: str,
    user_id: int,
    extension: str,
    podclub_id: int | None = None,
) -> str:
    unique = uuid.uuid4().hex
    if kind == "audio":
        return f"audio/{podclub_id}/{user_id}/{unique}.{extension}"
    if kind == "image":
        return f"images/{podclub_id}/{user_id}/{unique}.{extension}"
    if kind == "club_cover":
        return f"covers/{podclub_id}/{unique}.{extension}"
    return f"avatars/{user_id}/{unique}.{extension}"


def extract_object_path(reference: str) -> str | None:
    marker = f"/storage/v1/object/public/{settings.SUPABASE_STORAGE_BUCKET}/"
    if marker in reference:
        return reference.split(marker, 1)[1]
    if reference.startswith(("audio/", "images/", "covers/", "avatars/")):
        return reference
    return None


def _get_object_metadata(path: str) -> dict | None:
    require_storage()
    response = httpx.post(
        f"{_storage_url()}/object/info/{settings.SUPABASE_STORAGE_BUCKET}/{path}",
        headers=_headers(),
        json={},
        timeout=30,
    )
    if response.status_code == 200:
        data = response.json()
        if isinstance(data, dict):
            return data

    response = httpx.post(
        f"{_storage_url()}/object/list/{settings.SUPABASE_STORAGE_BUCKET}",
        headers=_headers(),
        json={"prefix": str(Path(path).parent).replace("\\", "/"), "limit": 100},
        timeout=30,
    )
    if response.status_code != 200:
        return None
    name = Path(path).name
    for item in response.json():
        if item.get("name") == name:
            return item
    return None


def validate_media_reference(
    kind: str,
    reference: str,
    user_id: int,
    podclub_id: int | None = None,
) -> str:
    if settings.ALLOW_EXTERNAL_MEDIA_URLS:
        return reference

    require_storage()
    path = extract_object_path(reference)
    if path is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Media must use our signed upload path or public URL")

    if kind == "audio":
        prefix = f"audio/{podclub_id}/{user_id}/"
        limit_mb = settings.MAX_AUDIO_MB
        allowed = ALLOWED_AUDIO_MIME_TYPES
    elif kind == "image":
        prefix = f"images/{podclub_id}/{user_id}/"
        limit_mb = settings.MAX_IMAGE_MB
        allowed = ALLOWED_IMAGE_MIME_TYPES
    elif kind == "club_cover":
        prefix = f"covers/{podclub_id}/" if podclub_id is not None else "covers/"
        limit_mb = settings.MAX_IMAGE_MB
        allowed = ALLOWED_IMAGE_MIME_TYPES
    else:
        prefix = f"avatars/{user_id}/"
        limit_mb = settings.MAX_IMAGE_MB
        allowed = ALLOWED_IMAGE_MIME_TYPES

    if not path.startswith(prefix):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Media path does not belong to the expected user or club",
        )

    metadata = _get_object_metadata(path)
    if metadata is None:
        delete_object(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded media object was not found")

    size = int(metadata.get("metadata", {}).get("size", metadata.get("size", 0)))
    mime_type = metadata.get("metadata", {}).get("mimetype") or metadata.get("mimetype")
    if size > limit_mb * 1024 * 1024:
        delete_object(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded media exceeds the size limit")
    if mime_type not in allowed:
        delete_object(path)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded media has a disallowed mime type")

    return (
        f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/public/"
        f"{settings.SUPABASE_STORAGE_BUCKET}/{path}"
    )
