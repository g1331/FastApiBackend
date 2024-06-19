from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy.future import select
from sqlalchemy.orm import joinedload

from database import orm
from database.models.user import User
from schemas import UserCreate, UserUpdate
from utils.token import get_password_hash, verify_password

# CRUD是指在做计算处理时的增加(Create)、读取查询(Retrieve)、更新(Update)和删除(Delete)几个单词的首字母简写。
# 主要被用在描述软件系统中DataBase或者持久层的基本操作功能。

async def get_user(user_id: int) -> Optional[User]:
    result = await orm.execute(select(User).filter(User.id == user_id).options(joinedload('*')))
    user = result.scalars().first()
    return user

async def get_user_by_username(username: str) -> Optional[User]:
    result = await orm.execute(select(User).filter(User.username == username).options(joinedload('*')))
    user = result.scalars().first()
    return user

async def create_user(user: UserCreate, is_admin: bool = False) -> User:
    hashed_password = get_password_hash(user.password)
    data = {
        "username": user.username,
        "hashed_password": hashed_password,
        "email": user.email,
        "is_active": True,
        "is_admin": is_admin,
        "avatar": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "login_count": 0,
        "last_login": None
    }
    await orm.add(User, data)
    return await get_user_by_username(user.username)

async def update_user(user_id: int, user_update: UserUpdate) -> Optional[User]:
    user = await get_user(user_id)
    if user:
        data = {
            "email": user_update.email,
            "updated_at": datetime.utcnow()
        }
        if user_update.password:
            data["hashed_password"] = get_password_hash(user_update.password)
        if user_update.avatar:
            data["avatar"] = user_update.avatar

        await orm.update(User, data, [User.id == user_id])
        user = await get_user(user_id)
    return user

# 更新登录时间
async def update_login_time(user: User) -> None:
    data = {
        "login_count": user.login_count + 1,
        "last_login": datetime.utcnow()
    }
    await orm.update(User, data, [User.id == user.id])

async def delete_user(user_id: int) -> Optional[User]:
    user = await get_user(user_id)
    if user:
        await orm.delete(User, [User.id == user_id])
    return user

async def authenticate_user(username: str, password: str) -> Optional[User]:
    user = await get_user_by_username(username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

async def get_users(skip: int = 0, limit: int = 10) -> Sequence[User]:
    result = await orm.execute(select(User).offset(skip).limit(limit).options(joinedload('*')))
    users = result.scalars().all()
    return users
