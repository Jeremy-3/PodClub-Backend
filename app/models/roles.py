import enum
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
    Enum,
)
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID


class RoleScope(str, enum.Enum):
    PLATFORM = "platform"
    CLUB = "club"


class Roles(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    uid = Column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        index=True,
        server_default=text("gen_random_uuid()"),
    )
    name = Column(String, unique=True)
    active = Column(Boolean, default=True)
    scope = Column(
        Enum(
            RoleScope,
            name="role_scope",
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
        default=RoleScope.PLATFORM,
        server_default=text("'platform'"),
    )
    is_system = Column(
        Boolean, nullable=False, default=False, server_default=text("false")
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

    # relations
    role_permissions = relationship(
        "RolePermission", back_populates="role", lazy="select"
    )
    users = relationship("Users", back_populates="role")
    podclub_members = relationship(
        "PodClubMembers",
        foreign_keys="PodClubMembers.role_id",
        back_populates="role",
    )
