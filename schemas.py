from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    username: str
    email: Optional[str] = None


class UserCreate(UserBase):
    password: str


class UserUpdate(UserBase):
    password: Optional[str] = None
    avatar: Optional[str] = None


class UserInDBBase(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    avatar: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    login_count: int
    last_login: Optional[datetime]

    class Config:
        from_attributes = True  # Pydantic V2 兼容性配置


class User(UserInDBBase):
    pass


class UserInDB(UserInDBBase):
    hashed_password: str

class TokenRequest(BaseModel):
    refresh_token: str
