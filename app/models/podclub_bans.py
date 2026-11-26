from datetime import datetime, timezone

from sqlalchemy import Column, ForeignKey, Integer, String, TIMESTAMP, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class PodClubBans(Base):
    __tablename__ = "podclub_bans"
    __table_args__ = (
        UniqueConstraint("podclub_id", "user_id", name="uq_podclub_ban"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        server_default=text("gen_random_uuid()"),
    )
    podclub_id = Column(
        Integer, ForeignKey("podclubs.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    banned_by_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reason = Column(String, nullable=True)
    created_at = Column(
        TIMESTAMP(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    podclub = relationship("PodClubs", back_populates="bans")
    user = relationship("Users", foreign_keys=[user_id], back_populates="podclub_bans")
    banned_by = relationship(
        "Users", foreign_keys=[banned_by_id], back_populates="podclub_bans_issued"
    )
