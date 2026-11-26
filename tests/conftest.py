from uuid import uuid4

import app.models  # noqa: F401
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.commands.seed import ROLE_NAMES, _seed_roles_and_permissions
from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.models.users import Users
from main import app

TEST_PASSWORD = "Password123!"


@pytest.fixture(scope="session")
def test_engine():
    test_url = make_url(settings.DATABASE_URL_TEST)
    app_url = make_url(settings.DATABASE_URL)
    if test_url.get_backend_name() != "postgresql" or not test_url.host:
        raise RuntimeError("DATABASE_URL_TEST must point to a real PostgreSQL server")
    if test_url.host not in {"localhost", "127.0.0.1", "::1"}:
        raise RuntimeError("DATABASE_URL_TEST must use localhost")
    if test_url.port not in (None, 5432):
        raise RuntimeError("DATABASE_URL_TEST must use port 5432")
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    same_host = test_url.host == app_url.host or (
        test_url.host in local_hosts and app_url.host in local_hosts
    )
    if (
        same_host
        and (test_url.port or 5432) == (app_url.port or 5432)
        and test_url.database == app_url.database
    ):
        raise RuntimeError("DATABASE_URL_TEST must not point to the application database")

    engine = create_engine(settings.DATABASE_URL_TEST, pool_pre_ping=True)
    if engine.dialect.name != "postgresql":
        engine.dispose()
        raise RuntimeError("Tests require PostgreSQL; SQLite is not supported")
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def seeded_core(test_engine):
    with Session(test_engine) as db:
        roles = _seed_roles_and_permissions(db)
        role_ids = {name: roles[name].id for name in ROLE_NAMES}
        db.commit()
    return role_ids


@pytest.fixture
def db_connection(test_engine, seeded_core):
    connection = test_engine.connect()
    transaction = connection.begin()
    try:
        yield connection
    finally:
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def db_session(db_connection):
    with Session(
        bind=db_connection,
        join_transaction_mode="create_savepoint",
    ) as db:
        yield db


@pytest.fixture
def client(db_connection):
    original_overrides = app.dependency_overrides.copy()

    def override_get_db():
        with Session(
            bind=db_connection,
            join_transaction_mode="create_savepoint",
        ) as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)


@pytest.fixture
def test_users(db_session, seeded_core):
    suffix = uuid4().hex
    password_hash = hash_password(TEST_PASSWORD)
    role_by_user = {
        "admin": "admin",
        "user_a": "user",
        "user_b": "user",
        "super_admin": "super_admin",
    }
    users = {}
    for label, role_name in role_by_user.items():
        username = f"test_{label}_{suffix}"
        user = Users(
            username=username,
            email=f"{username}@podclub.io",
            password_hash=password_hash,
            role_id=seeded_core[role_name],
            is_active=True,
        )
        db_session.add(user)
        db_session.flush()
        users[label] = {
            "id": user.id,
            "uid": str(user.uid),
            "username": user.username,
            "email": user.email,
            "token": create_access_token(user.id),
        }
    db_session.commit()
    return users


@pytest.fixture
def admin(test_users):
    return test_users["admin"]


@pytest.fixture
def user_a(test_users):
    return test_users["user_a"]


@pytest.fixture
def user_b(test_users):
    return test_users["user_b"]


@pytest.fixture
def super_admin_user(test_users):
    return test_users["super_admin"]


@pytest.fixture
def admin_token(admin):
    return admin["token"]


@pytest.fixture
def user_a_token(user_a):
    return user_a["token"]


@pytest.fixture
def user_b_token(user_b):
    return user_b["token"]
