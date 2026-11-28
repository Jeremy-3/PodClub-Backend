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
from app.models.episodes import Episodes
from app.models.message import Messages
from app.models.podclub_bans import PodClubBans
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.models.reports import ReportStatus, Reports
from app.models.users import Users
from main import app

TEST_PASSWORD = "Password123!"


def pytest_configure(config):
    test_url = str(settings.DATABASE_URL_TEST).lower()
    if "supabase" in test_url:
        raise RuntimeError(
            "DATABASE_URL_TEST must never point to Supabase"
        )


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

    engine = create_engine(
        settings.DATABASE_URL_TEST,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=5,
        max_overflow=5,
    )
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
        "second_admin": "admin",
        "club_owner": "user",
        "other_club_owner": "user",
        "moderator": "user",
        "member": "user",
        "outsider": "user",
        "banned_user": "user",
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
def second_admin(test_users):
    return test_users["second_admin"]


@pytest.fixture
def club_owner(test_users):
    return test_users["club_owner"]


@pytest.fixture
def other_club_owner(test_users):
    return test_users["other_club_owner"]


@pytest.fixture
def moderator(test_users):
    return test_users["moderator"]


@pytest.fixture
def member(test_users):
    return test_users["member"]


@pytest.fixture
def outsider(test_users):
    return test_users["outsider"]


@pytest.fixture
def banned_user(test_users):
    return test_users["banned_user"]


@pytest.fixture
def banned_from_club(db_session, club_context, test_users):
    user = db_session.get(Users, test_users["banned_user"]["id"])
    db_session.delete(club_context["banned_membership"])
    db_session.add(
        PodClubBans(
            podclub_id=club_context["club"].id,
            user_id=user.id,
            banned_by_id=test_users["club_owner"]["id"],
            reason="fixture club ban",
        )
    )
    db_session.commit()
    return test_users["banned_user"]


@pytest.fixture
def admin_token(admin):
    return admin["token"]


@pytest.fixture
def user_a_token(user_a):
    return user_a["token"]


@pytest.fixture
def user_b_token(user_b):
    return user_b["token"]


@pytest.fixture
def super_admin_token(super_admin_user):
    return super_admin_user["token"]


@pytest.fixture
def club_owner_token(club_owner):
    return club_owner["token"]


@pytest.fixture
def other_club_owner_token(other_club_owner):
    return other_club_owner["token"]


@pytest.fixture
def moderator_token(moderator):
    return moderator["token"]


@pytest.fixture
def member_token(member):
    return member["token"]


@pytest.fixture
def outsider_token(outsider):
    return outsider["token"]


@pytest.fixture
def banned_user_token(banned_user):
    return banned_user["token"]


@pytest.fixture
def club_context(db_session, seeded_core, test_users):
    suffix = uuid4().hex
    owner = db_session.get(Users, test_users["club_owner"]["id"])
    other_owner = db_session.get(Users, test_users["other_club_owner"]["id"])
    moderator = db_session.get(Users, test_users["moderator"]["id"])
    member = db_session.get(Users, test_users["member"]["id"])
    banned_user = db_session.get(Users, test_users["banned_user"]["id"])

    club = PodClubs(
        name=f"private_{suffix}",
        owner_id=owner.id,
        is_active=True,
        is_private=True,
    )
    other_club = PodClubs(
        name=f"other_private_{suffix}",
        owner_id=other_owner.id,
        is_active=True,
        is_private=True,
    )
    db_session.add_all([club, other_club])
    db_session.flush()

    moderator_membership = PodClubMembers(
        podclub_id=club.id,
        user_id=moderator.id,
        role_id=seeded_core["club_moderator"],
    )
    member_membership = PodClubMembers(
        podclub_id=club.id,
        user_id=member.id,
        role_id=seeded_core["club_member"],
    )
    banned_membership = PodClubMembers(
        podclub_id=club.id,
        user_id=banned_user.id,
        role_id=seeded_core["club_member"],
    )
    db_session.add_all(
        [moderator_membership, member_membership, banned_membership]
    )
    podcast = Podcasts(
        podclub_id=club.id,
        creator_id=owner.id,
        title=f"podcast_{suffix}",
        is_active=True,
    )
    other_podcast = Podcasts(
        podclub_id=other_club.id,
        creator_id=other_owner.id,
        title=f"other_podcast_{suffix}",
        is_active=True,
    )
    db_session.add_all([podcast, other_podcast])
    db_session.flush()

    owner_episode = Episodes(
        podcast_id=podcast.id,
        created_by_id=owner.id,
        title=f"owner_episode_{suffix}",
        audio_url="https://example.com/owner.mp3",
        duration=120,
    )
    member_episode = Episodes(
        podcast_id=podcast.id,
        created_by_id=member.id,
        title=f"member_episode_{suffix}",
        audio_url="https://example.com/member.mp3",
        duration=180,
    )
    db_session.add_all([owner_episode, member_episode])
    owner_message = Messages(
        podclub_id=club.id,
        sender_id=owner.id,
        body=f"owner_message_{suffix}",
    )
    member_message = Messages(
        podclub_id=club.id,
        sender_id=member.id,
        body=f"member_message_{suffix}",
    )
    db_session.add_all([owner_message, member_message])
    db_session.flush()

    own_report = Reports(
        reporter_id=member.id,
        reported_user_id=moderator.id,
        reason="Report in the owner's club",
        podclub_id=club.id,
        status=ReportStatus.PENDING,
    )
    other_report = Reports(
        reporter_id=other_owner.id,
        reported_user_id=owner.id,
        reason="Report in another club",
        podclub_id=other_club.id,
        status=ReportStatus.PENDING,
    )
    db_session.add_all([own_report, other_report])
    db_session.commit()

    return {
        "club": club,
        "other_club": other_club,
        "podcast": podcast,
        "other_podcast": other_podcast,
        "owner_episode": owner_episode,
        "member_episode": member_episode,
        "owner_message": owner_message,
        "member_message": member_message,
        "own_report": own_report,
        "other_report": other_report,
        "moderator_membership": moderator_membership,
        "member_membership": member_membership,
        "banned_membership": banned_membership,
    }
