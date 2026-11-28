import argparse
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.perm_names import (
    GRANTS,
    PERMISSION_NAMES,
    ROLE_NAMES,
    ROLE_CLUB_MEMBER,
    ROLE_CLUB_MODERATOR,
    ROLE_SCOPES,
    ROLE_SUPER_ADMIN,
    ROLE_USER,
)
from app.core.security import hash_password
from app.db.session import get_db
from app.models.episodes import Episodes
from app.models.invites import Invites
from app.models.message import Messages
from app.models.permissions import Permissions
from app.models.podclub_bans import PodClubBans
from app.models.podclub_members import PodClubMembers
from app.models.podclubs import PodClubs
from app.models.podcasts import Podcasts
from app.models.reports import ReportStatus, Reports
from app.models.role_permissions import RolePermission
from app.models.roles import RoleScope, Roles
from app.models.users import Users

ModelT = TypeVar("ModelT")

DUMMY_USERS = (
    ("alice", "alice@podclub.io"),
    ("bob", "bob@podclub.io"),
    ("carol", "carol@podclub.io"),
    ("dave", "dave@podclub.io"),
    ("erin", "erin@podclub.io"),
)
DUMMY_PASSWORD = "Password123!"
PERMISSION_NAMES_SORTED = tuple(sorted(PERMISSION_NAMES))


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


def _seed_roles_and_permissions(
    db: Session, reset_permissions: bool = False
) -> dict[str, Roles]:
    roles: dict[str, Roles] = {}
    for name in ROLE_NAMES:
        scope = RoleScope(ROLE_SCOPES[name])
        role, _ = get_or_create(
            db,
            Roles,
            {"name": name},
            {"active": True, "scope": scope, "is_system": True},
        )
        roles[name] = role
        if name == ROLE_SUPER_ADMIN and role.id != 1:
            raise RuntimeError(
                "The super_admin role must have id 1; seed an empty roles table first"
            )

    permissions: dict[str, Permissions] = {}
    for name in PERMISSION_NAMES_SORTED:
        permission, _ = get_or_create(
            db,
            Permissions,
            {"name": name},
            {
                "description": f"Permission: {name}",
                "category": name.split(".", maxsplit=1)[0],
            },
        )
        permissions[name] = permission

    for role_name in ROLE_NAMES:
        role = roles[role_name]
        for permission_name in sorted(GRANTS[role_name]):
            get_or_create(
                db,
                RolePermission,
                {
                    "role_id": role.id,
                    "permission_id": permissions[permission_name].id,
                },
            )

    if reset_permissions:
        _reset_system_role_permissions(db, roles)

    return roles


def _permission_reset_plan(
    db: Session,
) -> tuple[list[str], list[tuple[str, str]]]:
    stale_permissions = sorted(
        name
        for (name,) in db.query(Permissions.name).all()
        if name not in PERMISSION_NAMES
    )
    role_permission_rows = (
        db.query(Roles.name, Permissions.name)
        .join(RolePermission, RolePermission.role_id == Roles.id)
        .join(Permissions, Permissions.id == RolePermission.permission_id)
        .filter(Roles.name.in_(ROLE_NAMES))
        .all()
    )
    extra_grants = sorted(
        (role_name, permission_name)
        for role_name, permission_name in role_permission_rows
        if permission_name not in GRANTS[role_name]
    )
    return stale_permissions, extra_grants


def _print_permission_reset_plan(
    stale_permissions: list[str],
    extra_grants: list[tuple[str, str]],
) -> None:
    print("Permission reset preview:")
    print("Permissions to delete:")
    if stale_permissions:
        for permission_name in stale_permissions:
            print(f"  {permission_name}")
    else:
        print("  (none)")

    print("Extra system-role grants to remove:")
    if extra_grants:
        for role_name, permission_name in extra_grants:
            print(f"  {role_name}: {permission_name}")
    else:
        print("  (none)")

    if not stale_permissions and not extra_grants:
        print("No permission rows or role grants need removal.")


def _reset_system_role_permissions(
    db: Session,
    roles: dict[str, Roles],
) -> None:
    for role_name in ROLE_NAMES:
        role = roles[role_name]
        current_grants = (
            db.query(RolePermission, Permissions.name)
            .join(Permissions, Permissions.id == RolePermission.permission_id)
            .filter(RolePermission.role_id == role.id)
            .all()
        )
        for role_permission, permission_name in current_grants:
            if permission_name not in GRANTS[role_name]:
                db.delete(role_permission)

    stale_permissions = (
        db.query(Permissions)
        .filter(Permissions.name.notin_(PERMISSION_NAMES_SORTED))
        .all()
    )
    stale_ids = [permission.id for permission in stale_permissions]
    if stale_ids:
        db.query(RolePermission).filter(
            RolePermission.permission_id.in_(stale_ids)
        ).delete(synchronize_session=False)
        for permission in stale_permissions:
            db.delete(permission)


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


def _seed_dummy_data(db: Session, roles: dict[str, Roles]) -> None:
    users = {
        username: _get_or_create_user(
            db, username, email, DUMMY_PASSWORD, roles[ROLE_USER].id
        )
        for username, email in DUMMY_USERS
    }

    clubs: dict[str, PodClubs] = {}
    for name, owner_name in (
        ("PodClub Demo One", "alice"),
        ("PodClub Demo Two", "bob"),
        ("PodClub Demo Three", "carol"),
    ):
        club, _ = get_or_create(
            db,
            PodClubs,
            {"name": name},
            {
                "owner_id": users[owner_name].id,
                "is_active": True,
                "is_private": False,
            },
        )
        clubs[name] = club

    memberships = (
        ("PodClub Demo One", "bob", ROLE_CLUB_MODERATOR),
        ("PodClub Demo One", "dave", ROLE_CLUB_MEMBER),
        ("PodClub Demo Two", "carol", ROLE_CLUB_MODERATOR),
        ("PodClub Demo Two", "erin", ROLE_CLUB_MEMBER),
        ("PodClub Demo Two", "alice", ROLE_CLUB_MEMBER),
        ("PodClub Demo Three", "dave", ROLE_CLUB_MODERATOR),
        ("PodClub Demo Three", "bob", ROLE_CLUB_MEMBER),
        ("PodClub Demo Three", "erin", ROLE_CLUB_MEMBER),
    )
    role_ids = {name: role.id for name, role in roles.items()}
    for club_name, username, role_name in memberships:
        member, _ = get_or_create(
            db,
            PodClubMembers,
            {"podclub_id": clubs[club_name].id, "user_id": users[username].id},
            {"role_id": role_ids[role_name]},
        )
        if member.role_id != role_ids[role_name]:
            member.role_id = role_ids[role_name]
            db.flush()

    podcasts = (
        (
            "PodClub Demo Podcast One",
            "PodClub Demo One",
            "alice",
        ),
        (
            "PodClub Demo Podcast Two",
            "PodClub Demo Two",
            "bob",
        ),
    )
    podcast_by_title: dict[str, Podcasts] = {}
    for title, club_name, creator_name in podcasts:
        podcast, _ = get_or_create(
            db,
            Podcasts,
            {"title": title},
            {
                "podclub_id": clubs[club_name].id,
                "creator_id": users[creator_name].id,
            },
        )
        podcast_by_title[title] = podcast

    episodes = (
        ("PodClub Demo Podcast One", "PodClub Demo Episode One", 420, "alice"),
        ("PodClub Demo Podcast One", "PodClub Demo Episode Two", 510, "alice"),
        ("PodClub Demo Podcast Two", "PodClub Demo Episode Three", 360, "bob"),
    )
    for podcast_title, title, duration, creator_name in episodes:
        episode, _ = get_or_create(
            db,
            Episodes,
            {
                "podcast_id": podcast_by_title[podcast_title].id,
                "title": title,
            },
            {
                "created_by_id": users[creator_name].id,
                # Placeholder media URLs are intentionally external-only seed data.
                "audio_url": (
                    "https://example.com/audio/"
                    f"{title.lower().replace(' ', '-')}.mp3"
                ),
                "duration": duration,
            },
        )
        if episode.created_by_id is None:
            episode.created_by_id = users[creator_name].id
            db.flush()

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
        PodClubBans,
        {"podclub_id": club_id, "user_id": users["erin"].id},
        {"banned_by_id": users["alice"].id, "reason": "Seed club ban"},
    )
    get_or_create(
        db,
        Reports,
        {
            "reason": "Seed report for demonstration",
            "reporter_id": users["alice"].id,
            "reported_user_id": users["bob"].id,
        },
        {
            "podclub_id": club_id,
            "message_id": reply.id,
            "status": ReportStatus.PENDING,
        },
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


def seed(
    db: Session,
    include_dummy: bool = False,
    reset_permissions: bool = False,
) -> dict[str, Roles]:
    roles = _seed_roles_and_permissions(db, reset_permissions=reset_permissions)
    _seed_super_admin(db, roles[ROLE_SUPER_ADMIN].id)
    if include_dummy:
        _seed_dummy_data(db, roles)
    return roles


def _print_summary(db: Session, include_dummy: bool) -> None:
    counts = (
        ("roles", Roles),
        ("permissions", Permissions),
        ("role_permissions", RolePermission),
        ("users", Users),
        ("podclubs", PodClubs),
        ("podclub_members", PodClubMembers),
        ("podclub_bans", PodClubBans),
        ("podcasts", Podcasts),
        ("episodes", Episodes),
        ("messages", Messages),
        ("reports", Reports),
        ("invites", Invites),
    )
    print("Seed completed successfully.")
    print(
        "Counts: "
        + ", ".join(
            f"{name}={db.query(model).count()}" for name, model in counts
        )
    )
    if include_dummy:
        print("Dummy logins:")
        for _, email in DUMMY_USERS:
            print(f"  {email}")
        print(f"  Password: {DUMMY_PASSWORD}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed PodClub roles and permissions")
    parser.add_argument(
        "--dummy",
        action="store_true",
        help="Also create the demo users and content",
    )
    parser.add_argument(
        "--reset-permissions",
        action="store_true",
        help="After migration, reconcile system-role grants; take a pg_dump first",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm --reset-permissions without an interactive prompt",
    )
    args = parser.parse_args()
    if args.dummy and settings.APP_ENV == "production":
        parser.error("--dummy refuses to run when APP_ENV=production")
    if args.yes and not args.reset_permissions:
        parser.error("--yes can only be used with --reset-permissions")

    db_generator = get_db()
    db = next(db_generator)
    try:
        if args.reset_permissions:
            stale_permissions, extra_grants = _permission_reset_plan(db)
            _print_permission_reset_plan(stale_permissions, extra_grants)
            if not args.yes:
                try:
                    confirmation = input(
                        "This can remove grants and permission rows. "
                        "Type 'yes' to continue: "
                    )
                except EOFError as exc:
                    raise RuntimeError(
                        "Interactive confirmation unavailable; rerun with --yes "
                        "after taking a pg_dump backup."
                    ) from exc
                if confirmation != "yes":
                    db.rollback()
                    print("Permission reset cancelled; no changes made.")
                    return

        seed(
            db,
            include_dummy=args.dummy,
            reset_permissions=args.reset_permissions,
        )
        db.commit()
        _print_summary(db, include_dummy=args.dummy)
    except Exception:
        db.rollback()
        raise
    finally:
        db_generator.close()


if __name__ == "__main__":
    main()
