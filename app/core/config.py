from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str

    APP_ENV: str = "local"
    DEBUG: bool = False 

    ACCESS_TOKEN_EXPIRE_SECONDS: int = 18000
    OTP_TOKEN_EXPIRE_SECONDS: int = 300

    JWT_SECRET_KEY: str = "not-secret-key"
    JWT_ALGORITHM: str = "HS256"

    SUPERADMIN_NAME: Optional[str] = None
    SUPERADMIN_EMAIL: Optional[str] = None
    SUPERADMIN_PASSWORD: Optional[str] = None


    class Config:
        env_file = ".env"
        extra = "ignore"   # 🔥 IMPORTANT change

settings = Settings()