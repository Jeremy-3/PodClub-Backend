#/app/db/session.py
from app.core.config import settings
def get_db():
    if settings.APP_ENV == "local":
        from app.db.local_connector import DB_Session
    else:
        from app.db.cloud_connector import DB_Session

    db = DB_Session()
    try:
        yield db
    finally:
        db.close()