from sqlalchemy import Column,String,Integer,ForeignKey,DateTime,TIMESTAMP,func,Boolean,text
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID





class PodClubs(Base):
    
    __tablename__ = "podclubs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(UUID(as_uuid=True), unique=True, nullable=False, server_default=text("gen_random_uuid()"))
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    cover_url = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_private = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    
    # relationships
    owner = relationship("Users", back_populates="podclubs")
    members = relationship("PodClubMembers", back_populates="podclub")
    invites = relationship("Invites", back_populates="podclub")
    podcasts = relationship("Podcasts", back_populates="podclub")
    messages = relationship("Messages", back_populates="podclub")
    reports = relationship("Reports", back_populates="podclub")
    