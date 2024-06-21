import os
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext

from config import global_config

JWT_SECRET_KEY = global_config.jwt.secret_key
ALGORITHM = global_config.jwt.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = global_config.jwt.expiration_minutes
REFRESH_TOKEN_EXPIRE_DAYS = global_config.jwt.refresh_expiration_days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """
    获取密码的哈希值。

    这个函数使用bcrypt算法对指定的密码进行哈希。

    **参数**

    - `password`: 需要进行哈希的密码。

    **返回**

    返回密码的哈希值。
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码。

    这个函数比较明文密码和哈希密码，如果它们匹配，则返回True，否则返回False。

    **参数**

    - `plain_password`: 明文密码。
    - `hashed_password`: 哈希密码。

    **返回**

    如果密码匹配，返回True，否则返回False。
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建访问令牌。

    这个函数创建一个新的访问令牌，该令牌包含指定的数据，并在指定的时间后过期。

    **参数**

    - `data`: 需要包含在令牌中的数据。
    - `expires_delta`: 令牌的过期时间。如果没有指定，将使用默认的过期时间。

    **返回**

    返回新创建的访问令牌。
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建刷新令牌。

    这个函数创建一个新的刷新令牌，该令牌包含指定的数据，并在指定的时间后过期。

    **参数**

    - `data`: 需要包含在令牌中的数据。
    - `expires_delta`: 令牌的过期时间。如果没有指定，将使用默认的过期时间。

    **返回**

    返回新创建的刷新令牌。
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
