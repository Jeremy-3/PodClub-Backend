from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from app.core.config import Settings, normalize_database_url
from app.services import media
from app.schema.upload import UploadSignOut


def test_database_url_normalization():
    postgres_url = normalize_database_url(
        "postgres://user:p%40ss@db.example.com:5432/postgres"
    )
    assert postgres_url.startswith("postgresql+psycopg2://")
    assert "sslmode=require" in postgres_url
    assert "p%40ss" in postgres_url

    local_url = normalize_database_url(
        "postgresql://postgres:postgres@localhost:5432/podclub"
    )
    assert local_url.startswith("postgresql+psycopg2://")
    assert "sslmode" not in local_url


@pytest.mark.parametrize(
    ("kind", "filename", "mime"),
    [
        ("audio", "episode.mp3", "audio/mpeg"),
        ("image", "photo.jpg", "image/jpeg"),
        ("club_cover", "cover.png", "image/png"),
        ("avatar", "avatar.webp", "image/webp"),
    ],
)
def test_media_extension_and_mime_acceptance(kind, filename, mime):
    extension = media.validate_extension_and_mime(kind, filename, mime)
    assert extension


def test_media_path_rejects_foreign_user_club_and_kind(monkeypatch):
    monkeypatch.setattr(media.settings, "ALLOW_EXTERNAL_MEDIA_URLS", False)
    monkeypatch.setattr(media.settings, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(media.settings, "SUPABASE_STORAGE_BUCKET", "podclub-media")
    monkeypatch.setattr(media, "require_storage", lambda: None)
    monkeypatch.setattr(media, "_get_object_metadata", lambda path: {
        "size": 100,
        "mimetype": "image/png",
    })

    with pytest.raises(HTTPException) as exc:
        media.validate_media_reference(
            "avatar",
            "avatars/999/file.png",
            user_id=7,
        )
    assert exc.value.status_code == 400

    with pytest.raises(HTTPException):
        media.validate_media_reference(
            "image",
            "images/999/7/file.png",
            user_id=7,
            podclub_id=9,
        )
    assert exc.value.status_code == 400


def test_media_size_and_mime_rejection_delete_attempt(monkeypatch):
    deleted = []
    monkeypatch.setattr(media.settings, "ALLOW_EXTERNAL_MEDIA_URLS", False)
    monkeypatch.setattr(media.settings, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(media.settings, "SUPABASE_STORAGE_BUCKET", "podclub-media")
    monkeypatch.setattr(media.settings, "MAX_IMAGE_MB", 5)
    monkeypatch.setattr(media, "require_storage", lambda: None)
    monkeypatch.setattr(media, "delete_object", lambda path: deleted.append(path) or True)

    monkeypatch.setattr(
        media,
        "_get_object_metadata",
        lambda path: {"size": 6 * 1024 * 1024, "mimetype": "image/png"},
    )
    with pytest.raises(HTTPException) as exc:
        media.validate_media_reference(
            "image",
            "images/9/7/file.png",
            user_id=7,
            podclub_id=9,
        )
    assert exc.value.status_code == 400
    assert deleted

    deleted.clear()
    monkeypatch.setattr(
        media,
        "_get_object_metadata",
        lambda path: {"size": 100, "mimetype": "text/plain"},
    )
    with pytest.raises(HTTPException):
        media.validate_media_reference(
            "image",
            "images/9/7/file.png",
            user_id=7,
            podclub_id=9,
        )
    assert deleted


def test_external_media_bypass(monkeypatch):
    monkeypatch.setattr(media.settings, "ALLOW_EXTERNAL_MEDIA_URLS", True)
    assert media.validate_media_reference(
        "audio",
        "https://cdn.example.com/episode.mp3",
        user_id=7,
        podclub_id=9,
    ) == "https://cdn.example.com/episode.mp3"


def test_episode_duration_clamping():
    assert [media.clamp_audio_duration(value) for value in (-5, 1, 21600, 999999)] == [
        1,
        1,
        21600,
        21600,
    ]


def test_rls_migration_guard(db_session):
    missing = db_session.execute(
        text(
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind IN ('r', 'p')
              AND c.relrowsecurity = false
            ORDER BY c.relname
            """
        )
    ).scalars().all()
    assert missing == [], f"Public tables without RLS: {missing}"


def test_production_settings_reject_defaults_and_external_media(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "not-secret-key")
    with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
        Settings(APP_ENV="production")

    monkeypatch.setenv("JWT_SECRET_KEY", "a-long-production-secret")
    monkeypatch.setenv("ALLOW_EXTERNAL_MEDIA_URLS", "true")
    with pytest.raises(ValueError, match="ALLOW_EXTERNAL_MEDIA_URLS"):
        Settings(APP_ENV="production")


def test_sign_response_schema_never_contains_supabase_key():
    fields = set(UploadSignOut.model_fields)
    assert "service_role_key" not in fields
    assert "key" not in fields


def test_signed_upload_response_has_no_service_role_key(monkeypatch):
    class Response:
        status_code = 200

        def json(self):
            return {"token": "redacted-upload-token"}

    monkeypatch.setattr(media.settings, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(media.settings, "SUPABASE_SERVICE_ROLE_KEY", "secret")
    monkeypatch.setattr(media.settings, "SUPABASE_STORAGE_BUCKET", "podclub-media")
    monkeypatch.setattr(media.httpx, "post", lambda *args, **kwargs: Response())

    result = media.create_signed_upload_url("avatars/7/file.png")
    assert "secret" not in str(result)
    assert set(result) == {"signed_url", "token", "public_url"}


@pytest.mark.parametrize(
    ("kind", "podclub_id"),
    [
        ("audio", 9),
        ("image", 9),
        ("club_cover", 9),
        ("avatar", None),
    ],
)
def test_signed_upload_permission_kind_and_no_key(monkeypatch, kind, podclub_id):
    from app.routes import upload
    from app.schema.upload import UploadSignIn

    club = SimpleNamespace(id=podclub_id or 9)
    access = SimpleNamespace(
        user=SimpleNamespace(id=7),
        club_visible=lambda value: True,
        require=lambda permission, club=None: True,
    )
    payload = UploadSignIn(
        kind=kind,
        podclub_id=podclub_id,
        filename={
            "audio": "episode.mp3",
            "image": "photo.png",
            "club_cover": "cover.jpg",
            "avatar": "avatar.webp",
        }[kind],
        content_type={
            "audio": "audio/mpeg",
            "image": "image/png",
            "club_cover": "image/jpeg",
            "avatar": "image/webp",
        }[kind],
    )

    monkeypatch.setattr(upload.media, "require_storage", lambda: None)
    monkeypatch.setattr(upload.crud_podclub, "get", lambda db, podclub_id: club)
    monkeypatch.setattr(
        upload.media,
        "validate_extension_and_mime",
        lambda kind, filename, content_type: {
            "audio": "mp3",
            "image": "png",
            "club_cover": "jpg",
            "avatar": "webp",
        }[kind],
    )
    monkeypatch.setattr(
        upload.media,
        "build_object_path",
        lambda kind, user_id, extension, podclub_id=None:
        f"{kind}/{podclub_id or user_id}/{extension}",
    )
    monkeypatch.setattr(
        upload.media,
        "create_signed_upload_url",
        lambda path: {
            "signed_url": "https://signed.example.test/upload",
            "token": "redacted",
            "public_url": "https://cdn.example.test/file",
        },
    )
    monkeypatch.setattr(upload.settings, "SUPABASE_STORAGE_BUCKET", "podclub-media")

    response = upload.sign_upload(payload, db=object(), access=access)
    dumped = response.model_dump()
    assert "service_role_key" not in dumped
    assert "signed_url" in dumped["data"]
