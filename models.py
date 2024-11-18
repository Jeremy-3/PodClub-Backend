from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the database
db = SQLAlchemy()

# User model
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    reports = db.relationship('Report', foreign_keys='Report.user_id', backref='reporter', lazy=True)
    channels = db.relationship('Channel', secondary='channel_members', back_populates='members')

    # Validations
    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email:
            raise ValueError('Invalid email address')
        if len(email) > 120:
            raise ValueError('Email address too long')
        return email

    @validates('username')
    def validate_username(self, key, username):
        if len(username) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if len(username) > 80:
            raise ValueError('Username is too long')
        return username

    def set_password(self, password):
        """Set password hash."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        data = super().to_dict()
        data['channels'] = [channel.name for channel in self.channels]
        data['reports'] = [report.id for report in self.reports]
        return data

    # Serialization rules
    serialize_rules = ('-reports.reporter', '-channels.users')

# Report model
class Report(db.Model, SerializerMixin):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationship to the user who reported
    reported_user = db.relationship('User', foreign_keys=[reported_user_id], backref='reports_received')

    # Validations
    @validates('reason')
    def validate_reason(self, key, reason):
        if len(reason) < 10:
            raise ValueError('Reason for report must be at least 10 characters long')
        if len(reason) > 500:
            raise ValueError('Reason for report is too long')
        return reason

    def to_dict(self):
        data = super().to_dict()
        data['reported_user'] = self.reported_user.username
        return data

    # Serialization rules
    serialize_rules = ('-reported_user.reports_received',)

# Channel model
class Channel(db.Model, SerializerMixin):
    __tablename__ = 'channels'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Relationships
    owner = db.relationship('User', backref='owned_channels', lazy=True)
    members = db.relationship('User', secondary='channel_members', back_populates='channels')
    messages = db.relationship('Message', backref='channel', lazy=True)

    # Validations
    @validates('name')
    def validate_name(self, key, name):
        if len(name) < 3:
            raise ValueError('Channel name must be at least 3 characters long')
        if len(name) > 100:
            raise ValueError('Channel name is too long')
        return name

    def to_dict(self):
        data = super().to_dict()
        data['members'] = [member.username for member in self.members]
        data['messages'] = [message.id for message in self.messages]
        return data

    # Serialization rules
    serialize_rules = ('-owner.owned_channels', '-members.channels')

# Association table for Channel-Members
class ChannelMember(db.Model, SerializerMixin):
    __tablename__ = 'channel_members'
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    joined_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def to_dict(self):
        return {
            'channel_id': self.channel_id,
            'user_id': self.user_id,
            'joined_at': self.joined_at.isoformat()
        }

# Message model
class Message(db.Model, SerializerMixin):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    reply_to_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to sender
    sender = db.relationship('User', backref='messages_sent', lazy=True)
    replies = db.relationship('Message', backref=db.backref('parent', remote_side=[id]), lazy=True)

    def __repr__(self):
        return f'<Message {self.content[:20]}>'

    def to_dict(self):
        data = super().to_dict()
        data['sender'] = self.sender.username
        data['reply_to'] = self.reply_to_id 
        data['replies'] = [reply.to_dict() for reply in self.replies] 
        return data

    # Serialization rules
    serialize_rules = ('-sender.messages_sent', '-channel.messages')
