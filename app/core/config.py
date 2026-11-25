from typing import List, Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/podclub"
    DATABASE_URL_TEST: str = "postgresql://postgres:postgres@localhost:5432/podclub_test"

    APP_ENV: str = "local"
    DEBUG: bool = False

    ACCESS_TOKEN_EXPIRE_SECONDS: int = 18000
    OTP_TOKEN_EXPIRE_SECONDS: int = 300

    JWT_SECRET_KEY: str = "not-secret-key"
    JWT_ALGORITHM: str = "HS256"

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    SUPERADMIN_NAME: Optional[str] = None
    SUPERADMIN_EMAIL: Optional[str] = None
    SUPERADMIN_PASSWORD: Optional[str] = None

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.APP_ENV != "local" and self.JWT_SECRET_KEY == "not-secret-key":
            raise ValueError(
                "JWT_SECRET_KEY must be changed from the default in non-local environments"
            )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
