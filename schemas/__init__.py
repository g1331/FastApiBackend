from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime

class VerifyRequest(BaseModel):
    email: EmailStr = Field(
        ..., title="邮箱", description="邮箱", examples=["test@test.com"])
    code: str

class UserBase(BaseModel):
    username: str = Field(
        ..., min_length=4, max_length=15, title="用户名", description="用户名", examples=["g1331"])
    email: Optional[EmailStr] = Field(
        ..., title="邮箱", description="邮箱", examples=["test@test.com"])


class UserCreate(UserBase):
    """
    注册用户
    """
    password: Optional[str] = Field(
        ..., min_length=6, max_length=20, title="密码", description="密码", examples=["password"])

class ResponseRequestVerification(BaseModel):
    message: str = Field(..., title="消息", description="消息", examples=["验证码已发送至您的邮箱。"])

class UserUpdate(UserBase):
    password: Optional[str] = Field(
        None, min_length=6, max_length=20, title="密码", description="密码", examples=["password"])
    avatar: Optional[str] = Field(
        None, min_length=3, max_length=255, title="头像", description="头像",
        examples=["https://www.example.com/avatar.jpg"])


class UserInDBBase(UserBase):
    id: int = Field(..., title="用户ID", description="用户ID")
    is_active: bool = Field(..., title="是否激活", description="是否激活")
    is_admin: bool = Field(..., title="是否为管理员", description="是否为管理员")
    avatar: Optional[str] = Field(
        None, min_length=3, max_length=255, title="头像", description="头像",
        examples=["https://www.example.com/avatar.jpg"])
    created_at: datetime = Field(..., title="创建时间", description="创建时间")
    updated_at: datetime = Field(..., title="更新时间", description="更新时间")
    login_count: int = Field(..., title="登录次数", description="登录次数")
    last_login: Optional[datetime] = Field(
        None, title="最后登录时间", description="最后登录时间")

    class Config:
        from_attributes = True  # Pydantic V2 兼容性配置
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "g1331",
                "email": "test@email.com",
                "is_active": True,
                "is_admin": False,
                "avatar": "https://www.example.com/avatar.jpg",
                "created_at": "2021-01-01T00:00:00",
                "updated_at": "2021-01-01T00:00:00",
                "login_count": 0,
                "last_login": None
            }
        }


class User(UserInDBBase):
    """
    注册用户响应
    """
    pass


class UserInDB(UserInDBBase):
    hashed_password: str

class TokenRequest(BaseModel):
    refresh_token: str
