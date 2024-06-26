from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from loguru import logger
from starlette import status
from starlette.requests import Request
from starlette.responses import JSONResponse

import schemas
from database import crud
from utils.logger import SystemLogger
from utils.request_limit import get_rate_limiter
from utils.token import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, create_refresh_token

tokenRoute = APIRouter(
    prefix="/tokens",
    tags=["令牌"],
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Not found",
            "content": {"application/json": {"example": {"detail": "Not found"}}},
        }
    },
)


@tokenRoute.post(
    "",
    response_model=schemas.token.TokenResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "登录信息错误",
            "content": {
                "application/json": {
                    "example": {"detail": "登录信息错误", "headers": {"WWW-Authenticate": "Bearer"}}
                }
            },
        }
    },
    dependencies=[Depends(get_rate_limiter(max_calls=3, time_span=1))]
)
async def login_for_access_token(
        request: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
) -> JSONResponse:
    """
    用户登录接口。

    这个接口接收一个用户名和密码，验证用户的身份。如果验证成功，系统将会返回一个访问令牌和一个刷新令牌。

    **参数**

    - `form_data`: 包含用户名和密码的请求表单，包括：
        - `username`: 用户名。
        - `password`: 用户的密码。

    **返回**

    如果验证成功，系统将会返回一个访问令牌和一个刷新令牌。
    """
    user = await crud.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="登录信息错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(data={"sub": user.username})
    client_ip = request.client.host  # 获取客户端的IP地址
    logger.info(SystemLogger.user_action_msg(f"User {user.username} logged in，IP: {client_ip}"))  # 在日志中记录IP地址
    # 数据库记录登录时间
    await crud.update_login_time(user)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    )


@tokenRoute.post(
    "/refresh",
    response_model=schemas.token.RefreshTokenResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "description": "无效的刷新令牌",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid refresh token", "headers": {"WWW-Authenticate": "Bearer"}}
                }
            },
        }
    },
)
async def refresh_access_token(token_request: schemas.token.RefreshTokenRequest) -> JSONResponse:
    """
    刷新访问令牌接口。

    这个接口接收一个刷新令牌，然后返回一个新的访问令牌和刷新令牌。

    **参数**

    - `token_request`: 包含刷新令牌的请求对象。

    **返回**

    如果刷新令牌有效，系统将会返回一个新的访问令牌和刷新令牌。
    """
    user = await crud.get_user_by_username(token_request.refresh_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(data={"sub": user.username})  # 创建新的 Refresh Token
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    )
