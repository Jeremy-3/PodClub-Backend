from sqlalchemy import Column,String,Integer,ForeignKey,DateTime,TIMESTAMP,func,Boolean,text
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID




class Podcasts(Base):
    
    __tablename__ = "podcasts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(UUID(as_uuid=True), unique=True, nullable=False, server_default=text("gen_random_uuid()"))
    podclub_id = Column(Integer, ForeignKey("podclubs.id", ondelete="SET NULL"),nullable=True)
    creator_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    cover_url = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

    
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    
    # relationships
    creator = relationship("Users", back_populates="created_podcasts")
    podclub = relationship("PodClubs", back_populates="podcasts")
    episodes = relationship("Episodes", back_populates="podcast")