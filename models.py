from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from sqlalchemy import Column, Integer, String, Boolean, DateTime

from database import orm


class User(orm.Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, unique=True, index=True, nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    avatar = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    login_count = Column(Integer, default=0)
    last_login = Column(DateTime, nullable=True)
