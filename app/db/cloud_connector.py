from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

DATABASE_URL = settings.DATABASE_URL  # full connection string

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

DB_Session = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)
