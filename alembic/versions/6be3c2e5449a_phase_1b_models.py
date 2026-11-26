"""phase 1b models

Revision ID: 6be3c2e5449a
Revises: 5a48411fdd99
Create Date: 2026-11-26 11:41:13.917323

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "6be3c2e5449a"
down_revision: Union[str, Sequence[str], None] = "5a48411fdd99"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


PLATFORM_ROLES = ("super_admin", "admin", "user")
CLUB_ROLES = ("club_owner", "club_moderator", "club_member")
REPORT_STATUSES = ("pending", "reviewed", "resolved", "dismissed")


def _check_data_before_ddl(bind) -> None:
    for column in ("username", "email"):
        duplicates = bind.execute(
            sa.text(
                f"SELECT lower({column}), count(*) "
                f"FROM users GROUP BY lower({column}) "
                f"HAVING count(*) > 1 ORDER BY lower({column})"
            )
        ).all()
        if duplicates:
            values = ", ".join(f"{value!r} ({count})" for value, count in duplicates)
            raise RuntimeError(
                f"Cannot create the case-insensitive {column} index; "
                f"resolve these duplicates first: {values}"
            )

    invalid_statuses = bind.execute(
        sa.text(
            "SELECT DISTINCT status FROM reports "
            "WHERE status NOT IN ('pending', 'reviewed', 'resolved', 'dismissed') "
            "ORDER BY status"
        )
    ).scalars().all()
    if invalid_statuses:
        raise RuntimeError(
            "Cannot convert reports.status; unsupported values found: "
            + ", ".join(repr(value) for value in invalid_statuses)
        )

    existing_roles = set(
        bind.execute(sa.text("SELECT name FROM roles")).scalars().all()
    )
    missing_roles = [name for name in PLATFORM_ROLES if name not in existing_roles]
    if missing_roles:
        raise RuntimeError(
            "Run the Phase 1A seed before this migration; missing platform roles: "
            + ", ".join(missing_roles)
        )


def upgrade() -> None:
    bind = op.get_bind()
    _check_data_before_ddl(bind)

    role_scope = sa.Enum("platform", "club", name="role_scope")
    report_status = sa.Enum(*REPORT_STATUSES, name="report_status")
    role_scope.create(bind, checkfirst=True)
    report_status.create(bind, checkfirst=True)

    op.add_column(
        "roles",
        sa.Column(
            "scope",
            role_scope,
            server_default=sa.text("'platform'"),
            nullable=False,
        ),
    )
    op.add_column(
        "roles",
        sa.Column(
            "is_system",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    bind.execute(
        sa.text(
            "UPDATE roles SET scope = 'platform', is_system = TRUE "
            "WHERE name IN ('super_admin', 'admin', 'user')"
        )
    )
    for name in CLUB_ROLES:
        bind.execute(
            sa.text(
                "INSERT INTO roles "
                "(name, active, scope, is_system, created_at, updated_at) "
                "VALUES (:name, TRUE, 'club', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                "ON CONFLICT (name) DO UPDATE "
                "SET scope = 'club', is_system = TRUE"
            ),
            {"name": name},
        )

    op.add_column(
        "podclub_members",
        sa.Column("role_id", sa.Integer(), nullable=True),
    )
    bind.execute(
        sa.text(
            "UPDATE podclub_members AS member "
            "SET role_id = role.id "
            "FROM roles AS role "
            "WHERE role.name = 'club_member' AND member.role_id IS NULL"
        )
    )
    missing_membership_roles = bind.execute(
        sa.text("SELECT count(*) FROM podclub_members WHERE role_id IS NULL")
    ).scalar_one()
    if missing_membership_roles:
        raise RuntimeError(
            "Could not backfill podclub_members.role_id for every membership"
        )
    op.alter_column(
        "podclub_members",
        "role_id",
        existing_type=sa.Integer(),
        nullable=False,
    )
    op.create_foreign_key(
        "fk_podclub_members_role_id_roles",
        "podclub_members",
        "roles",
        ["role_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    op.create_table(
        "podclub_bans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "uid",
            sa.UUID(),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("podclub_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("banned_by_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["banned_by_id"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["podclub_id"], ["podclubs.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("podclub_id", "user_id", name="uq_podclub_ban"),
        sa.UniqueConstraint("uid"),
    )

    op.add_column(
        "episodes",
        sa.Column("created_by_id", sa.Integer(), nullable=True),
    )
    bind.execute(
        sa.text(
            "UPDATE episodes AS episode "
            "SET created_by_id = podcast.creator_id "
            "FROM podcasts AS podcast "
            "WHERE episode.podcast_id = podcast.id "
            "AND episode.created_by_id IS NULL"
        )
    )
    op.create_foreign_key(
        "fk_episodes_created_by_id_users",
        "episodes",
        "users",
        ["created_by_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.alter_column(
        "reports",
        "status",
        existing_type=sa.String(),
        type_=report_status,
        existing_nullable=False,
        server_default=sa.text("'pending'"),
        postgresql_using="status::report_status",
    )

    op.create_index(
        "uq_users_email_lower",
        "users",
        [sa.text("lower(email)")],
        unique=True,
    )
    op.create_index(
        "uq_users_username_lower",
        "users",
        [sa.text("lower(username)")],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    report_status = sa.Enum(*REPORT_STATUSES, name="report_status")
    role_scope = sa.Enum("platform", "club", name="role_scope")

    op.drop_index("uq_users_username_lower", table_name="users")
    op.drop_index("uq_users_email_lower", table_name="users")

    op.drop_constraint(
        "fk_podclub_members_role_id_roles",
        "podclub_members",
        type_="foreignkey",
    )
    op.drop_column("podclub_members", "role_id")

    op.drop_constraint(
        "fk_episodes_created_by_id_users",
        "episodes",
        type_="foreignkey",
    )
    op.drop_column("episodes", "created_by_id")
    op.drop_table("podclub_bans")

    bind.execute(
        sa.text(
            "DELETE FROM role_permissions AS role_permission "
            "USING roles AS role "
            "WHERE role_permission.role_id = role.id "
            "AND role.name IN ('club_owner', 'club_moderator', 'club_member')"
        )
    )
    bind.execute(
        sa.text(
            "DELETE FROM roles "
            "WHERE name IN ('club_owner', 'club_moderator', 'club_member')"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE roles SET is_system = FALSE "
            "WHERE name IN ('super_admin', 'admin', 'user')"
        )
    )

    op.alter_column(
        "reports",
        "status",
        existing_type=report_status,
        type_=sa.String(),
        existing_nullable=False,
        server_default=None,
        postgresql_using="status::text",
    )
    report_status.drop(bind, checkfirst=True)
    op.drop_column("roles", "is_system")
    op.drop_column("roles", "scope")
    role_scope.drop(bind, checkfirst=True)
