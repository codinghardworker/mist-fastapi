from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from datetime import datetime
from sqlalchemy.orm import relationship
from database.db.db_connection import Base

class AppSettings(Base):
    __tablename__ = 'app_settings'
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(String, nullable=False)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, ForeignKey('users.id'), nullable=True)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="user")  # 'user' or 'admin'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    allowed_tags = Column(String, default="1001")  # Comma-separated tags
    
    updated_settings = relationship("AppSettings", backref="updater")

class BlacklistedToken(Base):
    __tablename__ = 'blacklisted_tokens'
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False)
    reason = Column(String, nullable=True)
    blacklisted_at = Column(DateTime, default=datetime.utcnow)

class UserPushLimit(Base):
    __tablename__ = "user_push_limits"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    max_concurrent_pushes = Column(Integer, default=1)
    current_pushes = Column(Integer, default=0)