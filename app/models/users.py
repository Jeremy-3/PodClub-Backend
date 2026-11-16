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
    password_hash = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    banned_at = Column(TIMESTAMP(timezone=True), nullable=True)  # no default
    banned_at = Column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
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
    sent_messages = relationship("Messages", back_populates="sender")
    reports_made = relationship("Reports", back_populates="reporter")
    reports_against = relationship("Reports", back_populates="reported_user")
