from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

import schemas.user
from database import crud
from utils.token import JWT_SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/tokens")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> schemas.user.User:
    """
    获取当前用户。

    这个函数会解码 JWT，然后根据其中的用户名获取用户。如果 JWT 无效，或者用户不存在，那么会抛出一个 HTTP 异常。

    **参数**

    - `token`: JWT。

    **返回**

    返回当前用户。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await crud.get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user

async def get_active_user(current_user: schemas.user.User = Depends(get_current_user)) -> schemas.user.User:
    """
    获取当前已激活的用户。

    这个函数会检查当前用户是否已激活。如果用户未激活，那么会抛出一个 HTTP 异常。

    **参数**

    - `current_user`: 当前用户。

    **返回**

    返回当前已激活的用户。
    """
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="已禁用的用户")
    return current_user

async def get_current_active_user(current_user: schemas.user.User = Depends(get_active_user)) -> schemas.user.User:
    """
    获取当前已激活的用户。

    这个函数会返回当前已激活的用户。

    **参数**

    - `current_user`: 当前用户。

    **返回**

    返回当前已激活的用户。
    """
    return current_user

async def get_current_active_admin(current_user: schemas.user.User = Depends(get_active_user)) -> schemas.user.User:
    """
    获取当前已激活的管理员。

    这个函数会检查当前用户是否是管理员。如果用户不是管理员，那么会抛出一个 HTTP 异常。

    **参数**

    - `current_user`: 当前用户。

    **返回**

    返回当前已激活的管理员。
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="权限不足！只有管理员可以访问此接口")
    return current_user
