from sqlalchemy import Column,String,Integer,ForeignKey,DateTime,TIMESTAMP,func,Boolean,text
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID




class Reports(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(UUID(as_uuid=True), unique=True, nullable=False, server_default=text("gen_random_uuid()"))
    reporter_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    reported_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    reason = Column(String, nullable=False)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="SET NULL"),nullable=True)
    podclub_id = Column(Integer, ForeignKey("podclubs.id", ondelete="SET NULL"),nullable=True)
    status = Column(String, nullable=False, default="pending")  # pending, reviewed, resolved
    reviewed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True)
    
    
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    
    # relationships
    reporter = relationship("Users", foreign_keys=[reporter_id], back_populates="reports_made")
    reported_user = relationship("Users", foreign_keys=[reported_user_id], back_populates="reports_against")
    message = relationship("Messages", back_populates="reports")
    podclub = relationship("PodClubs", back_populates="reports")