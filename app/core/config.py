import json
from typing import Annotated, List, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def normalize_database_url(value: str) -> str:
    if value.startswith("postgres://"):
        value = "postgresql+psycopg2://" + value[len("postgres://") :]
    elif value.startswith("postgresql://"):
        value = "postgresql+psycopg2://" + value[len("postgresql://") :]

    parsed = urlsplit(value)
    if parsed.hostname and parsed.hostname.lower() not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        query = parsed.query
        has_sslmode = any(
            item.split("=", 1)[0].lower() == "sslmode"
            for item in query.split("&")
            if item
        )
        if not has_sslmode:
            query = f"{query}&sslmode=require" if query else "sslmode=require"
            value = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)
            )
    return value


class Settings(BaseSettings):
    DATABASE_URL: str = (
        "postgresql+psycopg2://postgres:postgres@localhost:5432/podclub"
    )
    DATABASE_URL_TEST: str = (
        "postgresql+psycopg2://postgres:postgres@localhost:5432/podclub_test"
    )

    APP_ENV: str = "local"
    DEBUG: bool = False
    ENABLE_DOCS: bool = True

    ACCESS_TOKEN_EXPIRE_SECONDS: int = 18000

    JWT_SECRET_KEY: str = "not-secret-key"
    JWT_ALGORITHM: str = "HS256"

    CORS_ORIGINS: Annotated[
        List[str],
        NoDecode,
    ] = ["http://localhost:3000", "http://localhost:5173"]
    CORS_ORIGIN_REGEX: Optional[str] = None

    SUPABASE_URL: Optional[str] = None
    SUPABASE_SERVICE_ROLE_KEY: Optional[str] = None
    SUPABASE_STORAGE_BUCKET: str = "podclub-media"
    MAX_AUDIO_MB: int = 50
    MAX_IMAGE_MB: int = 5
    ALLOW_EXTERNAL_MEDIA_URLS: bool = False

    RATE_LIMIT_ENABLED: bool = True
    LOGIN_RATE_LIMIT: str = "10/minute"
    REGISTER_RATE_LIMIT: str = "10/hour"
    PUBLIC_PODCLUBS_RATE_LIMIT: str = "60/minute"
    INVITE_PREVIEW_RATE_LIMIT: str = "10/minute"

    SUPERADMIN_NAME: Optional[str] = None
    SUPERADMIN_EMAIL: Optional[str] = None
    SUPERADMIN_PASSWORD: Optional[str] = None

    @field_validator("DATABASE_URL", "DATABASE_URL_TEST", mode="before")
    @classmethod
    def normalize_database_urls(cls, value: str) -> str:
        return normalize_database_url(value)

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: List[str] | str) -> List[str]:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                parsed = json.loads(stripped)
                if not isinstance(parsed, list):
                    raise ValueError("CORS_ORIGINS JSON value must be a list")
                value = parsed
            else:
                value = stripped.split(",")
        return [origin.strip() for origin in value if origin.strip()]

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.APP_ENV != "local" and self.JWT_SECRET_KEY == "not-secret-key":
            raise ValueError(
                "JWT_SECRET_KEY must be changed from the default in non-local environments"
            )
        if self.APP_ENV == "production" and self.ALLOW_EXTERNAL_MEDIA_URLS:
            raise ValueError(
                "ALLOW_EXTERNAL_MEDIA_URLS cannot be enabled in production"
            )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
