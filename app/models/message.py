from sqlalchemy import Column,String,Integer,ForeignKey,DateTime,TIMESTAMP,func,Boolean,text,Index
from datetime import datetime, timezone
from sqlalchemy.orm import relationship
from app.db.base import Base
from sqlalchemy.dialects.postgresql import UUID




class Messages(Base):
    
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uid = Column(UUID(as_uuid=True), unique=True, nullable=False, server_default=text("gen_random_uuid()"))
    podclub_id = Column(Integer, ForeignKey("podclubs.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),nullable=True,index=True)
    parent_message_id = Column(Integer, ForeignKey("messages.id", ondelete="SET NULL"),nullable=True,index=True)
    body = Column(String, nullable=True)
    image_url = Column(String, nullable=True)
    is_edited = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False,index=True)
    updated_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (Index("ix_messages_podclub_id_created_at", "podclub_id", "created_at"),)
    
    
    # relationships
    sender = relationship("Users", foreign_keys=[sender_id], back_populates="sent_messages")
    parent_message = relationship("Messages", remote_side=[id], back_populates="replies")
    replies = relationship("Messages", back_populates="parent_message")
    podclub = relationship("PodClubs", back_populates="messages")
    reports = relationship("Reports", back_populates="message")
    