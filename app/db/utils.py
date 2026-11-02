from contextlib import contextmanager
from app.db.session import get_db

@contextmanager
def db_context():
    db = next(get_db())
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()