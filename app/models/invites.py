from sqlalchemy import Column,String,Integer,ForeignKey,DateTime,TIMESTAMP,func,Boolean,text
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID




class Invites(Base):
    
    __tablename__ = "invites"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(UUID(as_uuid=True), unique=True, nullable=False, server_default=text("gen_random_uuid()"))
    podclub_id = Column(Integer, ForeignKey("podclubs.id", ondelete="CASCADE"), nullable=False)
    email = Column(String, nullable=False)
    token = Column(String, nullable=False,unique=True,index=True)
    invited_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    accepted_at = Column(TIMESTAMP(timezone=True), default=None, nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc) + timedelta(days=2), nullable=False)
    max_uses = Column(Integer, default=0, nullable=False)
    use_count = Column(Integer, default=0, nullable=False)
    
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    
    # relationships
    podclub = relationship("PodClubs", back_populates="invites")
    invited_by = relationship("Users", back_populates="sent_invites")