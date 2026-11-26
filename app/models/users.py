from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    DateTime,
    TIMESTAMP,
    func,
    Boolean,
    text,
    Index,
)
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        server_default=text("gen_random_uuid()"),
    )
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    __table_args__ = (
        Index("uq_users_username_lower", func.lower(username), unique=True),
        Index("uq_users_email_lower", func.lower(email), unique=True),
    )
    password_hash = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    banned_at = Column(TIMESTAMP(timezone=True), nullable=True)  # no default
    role_id = Column(
        Integer, ForeignKey("roles.id", ondelete="SET NULL"), nullable=True
    )

    created_at = Column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )  # timezone = True ensures that the column is timezone-aware. # lambda function, ensures that a new timestamp is generated each time a record is created or updated.
    updated_at = Column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # relationships
    role = relationship("Roles", back_populates="users")
    podclubs = relationship("PodClubs", back_populates="owner")
    podclub_memberships = relationship("PodClubMembers", back_populates="user")
    sent_invites = relationship("Invites", back_populates="invited_by")
    created_podcasts = relationship("Podcasts", back_populates="creator")
    created_episodes = relationship(
        "Episodes",
        foreign_keys="Episodes.created_by_id",
        back_populates="created_by",
    )
    sent_messages = relationship("Messages", foreign_keys="Messages.sender_id", back_populates="sender")
    reports_made = relationship("Reports", foreign_keys="Reports.reporter_id", back_populates="reporter")
    reports_against = relationship("Reports", foreign_keys="Reports.reported_user_id", back_populates="reported_user")
    reports_reviewed = relationship("Reports", foreign_keys="Reports.reviewed_by_id", back_populates="reviewed_by")
    podclub_bans = relationship(
        "PodClubBans",
        foreign_keys="PodClubBans.user_id",
        back_populates="user",
    )
    podclub_bans_issued = relationship(
        "PodClubBans",
        foreign_keys="PodClubBans.banned_by_id",
        back_populates="banned_by",
    )
