import argparse
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.db.session import get_db
from app.models.episodes import Episodes
from app.models.invites import Invites
from app.models.message import Messages
from app.models.permissions import Permissions
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.models.reports import Reports
from app.models.role_permissions import RolePermission
from app.models.roles import Roles
from app.models.users import Users

ModelT = TypeVar("ModelT")

ROLE_NAMES = ("super_admin", "admin", "user")

PERMISSION_NAMES = (
    "podclub.create",
    "podclubs.view_all",
    "podclub.view_one",
    "podclub.update",
    "podclub.delete",
    "podclub_member.create",
    "podclub_members.view_all",
    "podclub_member.view_one",
    "podclub_member.update",
    "podclub_member.delete",
    "invite.create",
    "invites.view_all",
    "invite.view_one",
    "invite.update",
    "invite.delete",
    "podcast.create",
    "podcasts.view_all",
    "podcast.view_one",
    "podcast.update",
    "podcast.delete",
    "episode.create",
    "episodes.view_all",
    "episode.view_one",
    "episode.update",
    "episode.delete",
    "message.create",
    "messages.view_all",
    "message.view_one",
    "message.update",
    "message.delete",
    "report.create",
    "reports.view_all",
    "report.view_one",
    "report.update",
    "report.delete",
    "user.create",
    "users.view_all",
    "user.view_one",
    "user.update",
    "role.create",
    "roles.view_all",
    "role.view_one",
    "role.update",
    "role.delete",
    "permission.create",
    "permissions.view_all",
    "permission.view_one",
    "permission.update",
    "permission.delete",
    "permissions.manage",
    "roles.view",
)

# TODO(1B): Replace these temporary grants with ownership and membership checks.
USER_PERMISSION_NAMES = (
    "podclub.create",
    "podclubs.view_all",
    "podclub.view_one",
    "podclub.update",
    "podclub.delete",
    "podclub_member.create",
    "podclub_members.view_all",
    "podclub_member.view_one",
    "podclub_member.update",
    "podclub_member.delete",
    "invite.create",
    "invites.view_all",
    "invite.view_one",
    "invite.update",
    "invite.delete",
    "podcast.create",
    "podcasts.view_all",
    "podcast.view_one",
    "podcast.update",
    "podcast.delete",
    "episode.create",
    "episodes.view_all",
    "episode.view_one",
    "episode.update",
    "episode.delete",
    "message.create",
    "messages.view_all",
    "message.view_one",
    "message.update",
    "message.delete",
    "report.create",
    "user.view_one",
)

DUMMY_USERS = (
    ("alice", "alice@podclub.io"),
    ("bob", "bob@podclub.io"),
    ("carol", "carol@podclub.io"),
    ("dave", "dave@podclub.io"),
    ("erin", "erin@podclub.io"),
)


def get_or_create(
    db: Session,
    model: type[ModelT],
    filters: dict[str, Any],
    values: dict[str, Any] | None = None,
) -> tuple[ModelT, bool]:
    instance = db.query(model).filter_by(**filters).first()
    if instance is not None:
        return instance, False

    instance = model(**filters, **(values or {}))
    db.add(instance)
    db.flush()
    return instance, True


def _get_or_create_user(
    db: Session,
    username: str,
    email: str,
    password: str,
    role_id: int,
) -> Users:
    user = (
        db.query(Users)
        .filter(
            or_(
                func.lower(Users.username) == username.lower(),
                func.lower(Users.email) == email.lower(),
            )
        )
        .first()
    )
    if user is not None:
        if user.username != username or user.email.lower() != email.lower():
            raise RuntimeError(
                f"Seed identity {username!r} conflicts with an existing user"
            )
        return user

    user = Users(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=role_id,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def _seed_roles_and_permissions(db: Session) -> dict[str, Roles]:
    roles: dict[str, Roles] = {}
    for name in ROLE_NAMES:
        role, _ = get_or_create(
            db, Roles, {"name": name}, {"active": True}
        )
        roles[name] = role
        if name == "super_admin" and role.id != 1:
            raise RuntimeError(
                "The super_admin role must have id 1; seed an empty roles table first"
            )

    permissions: dict[str, Permissions] = {}
    for name in PERMISSION_NAMES:
        permission, _ = get_or_create(
            db,
            Permissions,
            {"name": name},
            {
                "description": f"Route permission: {name}",
                "category": name.split(".", maxsplit=1)[0],
            },
        )
        permissions[name] = permission

    management_prefixes = ("role.", "roles.", "permission.", "permissions.")
    admin_permission_names = tuple(
        name
        for name in PERMISSION_NAMES
        if not name.startswith(management_prefixes)
    )
    role_grants = {
        "super_admin": PERMISSION_NAMES,
        "admin": admin_permission_names,
        "user": USER_PERMISSION_NAMES,
    }

    for role_name in ROLE_NAMES:
        role = roles[role_name]
        for permission_name in role_grants[role_name]:
            get_or_create(
                db,
                RolePermission,
                {
                    "role_id": role.id,
                    "permission_id": permissions[permission_name].id,
                },
            )

    return roles


def _seed_super_admin(db: Session, role_id: int) -> Users:
    name = settings.SUPERADMIN_NAME
    email = settings.SUPERADMIN_EMAIL
    password = settings.SUPERADMIN_PASSWORD
    if not name or not name.strip() or not email or not email.strip() or not password:
        raise RuntimeError(
            "Set SUPERADMIN_NAME, SUPERADMIN_EMAIL, and SUPERADMIN_PASSWORD in .env"
        )

    user = _get_or_create_user(db, name, email, password, role_id)
    if user.role_id != role_id:
        user.role_id = role_id
        db.flush()
    return user


def _seed_dummy_data(db: Session, user_role_id: int) -> None:
    users = {
        username: _get_or_create_user(
            db, username, email, "Password123!", user_role_id
        )
        for username, email in DUMMY_USERS
    }

    clubs: dict[str, PodClubs] = {}
    for name, owner in (
        ("PodClub Demo One", "alice"),
        ("PodClub Demo Two", "bob"),
        ("PodClub Demo Three", "carol"),
    ):
        club, _ = get_or_create(
            db,
            PodClubs,
            {"name": name},
            {"owner_id": users[owner].id, "is_active": True, "is_private": False},
        )
        clubs[name] = club

    memberships = (
        ("PodClub Demo One", "alice"),
        ("PodClub Demo One", "bob"),
        ("PodClub Demo Two", "bob"),
        ("PodClub Demo Two", "carol"),
        ("PodClub Demo Three", "carol"),
        ("PodClub Demo Three", "dave"),
        ("PodClub Demo Three", "erin"),
    )
    for club_name, username in memberships:
        get_or_create(
            db,
            PodClubMembers,
            {"podclub_id": clubs[club_name].id, "user_id": users[username].id},
        )

    podcast_one, _ = get_or_create(
        db,
        Podcasts,
        {"title": "PodClub Demo Podcast One"},
        {"podclub_id": clubs["PodClub Demo One"].id, "creator_id": users["alice"].id},
    )
    podcast_two, _ = get_or_create(
        db,
        Podcasts,
        {"title": "PodClub Demo Podcast Two"},
        {"podclub_id": clubs["PodClub Demo Two"].id, "creator_id": users["bob"].id},
    )

    episodes = (
        (podcast_one, "PodClub Demo Episode One", 420),
        (podcast_one, "PodClub Demo Episode Two", 510),
        (podcast_two, "PodClub Demo Episode Three", 360),
    )
    for podcast, title, duration in episodes:
        get_or_create(
            db,
            Episodes,
            {"podcast_id": podcast.id, "title": title},
            {
                "audio_url": f"https://example.com/audio/{title.lower().replace(' ', '-')}.mp3",
                "duration": duration,
            },
        )

    club_id = clubs["PodClub Demo One"].id
    root_message, _ = get_or_create(
        db,
        Messages,
        {
            "podclub_id": club_id,
            "body": "What did everyone think of the new episode?",
            "parent_message_id": None,
        },
        {"sender_id": users["alice"].id},
    )
    reply, _ = get_or_create(
        db,
        Messages,
        {
            "podclub_id": club_id,
            "body": "I liked the interview section.",
            "parent_message_id": root_message.id,
        },
        {"sender_id": users["bob"].id},
    )
    get_or_create(
        db,
        Messages,
        {
            "podclub_id": club_id,
            "body": "Same here; the guest had great insights.",
            "parent_message_id": reply.id,
        },
        {"sender_id": users["carol"].id},
    )

    get_or_create(
        db,
        Reports,
        {
            "reason": "Seed report for demonstration",
            "reporter_id": users["alice"].id,
            "reported_user_id": users["bob"].id,
        },
        {"podclub_id": club_id, "message_id": reply.id, "status": "pending"},
    )

    get_or_create(
        db,
        Invites,
        {"podclub_id": club_id, "email": "invitee@podclub.io"},
        {
            "token": secrets.token_urlsafe(24),
            "invited_by_id": users["alice"].id,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=2),
            "max_uses": 1,
        },
    )


def seed(db: Session, include_dummy: bool = False) -> None:
    roles = _seed_roles_and_permissions(db)
    _seed_super_admin(db, roles["super_admin"].id)
    if include_dummy:
        _seed_dummy_data(db, roles["user"].id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed PodClub roles and permissions")
    parser.add_argument(
        "--dummy",
        action="store_true",
        help="Also create demo users, clubs, podcasts, episodes, messages, report, and invite",
    )
    args = parser.parse_args()

    db_generator = get_db()
    db = next(db_generator)
    try:
        seed(db, include_dummy=args.dummy)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db_generator.close()

    print("Seed completed successfully.")


if __name__ == "__main__":
    main()
