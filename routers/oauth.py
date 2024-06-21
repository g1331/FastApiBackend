import os
import random
import string
from datetime import timedelta

import httpx
from fastapi import APIRouter, HTTPException
from starlette.responses import RedirectResponse

import schemas
from config import global_config
from database import crud
from utils.logger import SystemLogger
from utils.token import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, create_refresh_token

oauthRoute = APIRouter(
    prefix="/oauth",
    tags=["OAuth"],
    responses={404: {"description": "Not found"}},
)

GITHUB_CLIENT_ID = global_config.oauth.github_client_id
GITHUB_CLIENT_SECRET = global_config.oauth.github_client_secret


# NOTE: 使用github登录，访问oauth重定向到github登录页面
@oauthRoute.get("")
async def github_login():
    """
    GitHub OAuth登录接口。

    此接口将用户重定向到GitHub的登录页面进行OAuth授权。当用户点击授权后，GitHub会将用户重定向回我们的应用，并在查询参数中提供一个授权码。

    **返回**:

    - RedirectResponse: 一个重定向响应，将用户重定向到GitHub的登录页面。
    """
    return RedirectResponse(
        url=f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}"
            f"&redirect_uri=http://{os.getenv('APP_HOST')}:{os.getenv('app_port')}/v1/oauth/redirect"
    )


# NOTE: github登录成功后，github会重定向到这个地址
@oauthRoute.get("/redirect")
async def github_redirect(code: str):
    """
    GitHub OAuth重定向接口。

    此接口处理GitHub OAuth的重定向。当用户在GitHub上完成授权后，GitHub会将用户重定向到此接口，并在查询参数中提供一个授权码。

    此接口将使用此授权码从GitHub获取访问令牌，然后使用此访问令牌获取用户的GitHub信息。如果用户在我们的系统中不存在，我们将创建一个新的用户。

    **参数**:

    - code (str): GitHub OAuth提供的授权码。

    **返回**:

    - dict: 包含消息和新创建或已存在的用户信息的字典。如果在创建新用户时出现问题，此接口将返回HTTP 500错误。
    """
    # 请求用户身份信息
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://github.com/login/oauth/access_token"
            f"?client_id={GITHUB_CLIENT_ID}"
            f"&client_secret={GITHUB_CLIENT_SECRET}"
            f"&code={code}",
            headers={"Accept": "application/json"}
        )

    if response.json().get("error"):
        raise HTTPException(status_code=400, detail="GitHub OAuth failed.")

    try:
        #  获取access_token
        access_token = response.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="GitHub OAuth failed.")
        #  请求用户信息
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {access_token}"}
            )
        user_info = response.json()
    except Exception as e:
        SystemLogger.error(SystemLogger.AuthLogger, f"无法获取用户信息，详细信息：{e}")
        raise HTTPException(status_code=500, detail="无法获取用户信息。")

    # 1. 如果未注册，自动注册
    # 提取用户信息进行注册
    # 1. 获取用户名
    user_name = user_info["login"]
    # 2. 获取邮箱
    user_email = user_info["email"]

    # 先检查用户名是否存在，如果存在则在此用户名后 添加 #+6位的随机合法字符
    existing_user = await crud.get_user_by_username(user_name)
    if existing_user:
        # 定义合法字符
        valid_chars = string.ascii_letters + string.digits
        # 生成6位随机字符
        random_chars = ''.join(random.choices(valid_chars, k=6))
        # 在用户名后添加随机字符
        user_name = f"{user_name}_{random_chars}"

    # 获取用户id，检查是否已经存在
    user_github_id = user_info["id"]
    existing_user = await crud.get_user_by_github_id(user_github_id)
    if existing_user:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": existing_user.username}, expires_delta=access_token_expires)
        refresh_token = create_refresh_token(data={"sub": existing_user.username})
        # 数据库记录登录时间
        user_base = await crud.get_user_by_username(existing_user.username)
        await crud.update_login_time(user_base)
        return {
            "message": "登录成功",
            "user": {
                "id": existing_user.id,
                "username": existing_user.username,
                "email": existing_user.email,
                "is_active": existing_user.is_active,
                "is_admin": existing_user.is_admin,
            },
            "tokens": {
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        }

    # 如果用户不存在，创建新用户
    try:
        user_data: schemas.UserCreate = schemas.UserCreate(
            username=user_name,
            password=None,
            email=user_email,
        )
        new_user = await crud.create_user(user_data, is_third_party=True, github_id=user_github_id)
        SystemLogger.success(SystemLogger.AuthLogger, f"创建新用户 {user_name} 成功。")
    except Exception as e:
        SystemLogger.error(SystemLogger.AuthLogger, f"无法创建用户数据，详细信息：{e}")
        raise HTTPException(status_code=500, detail="用户数据创建失败。")

    if new_user is None:
        raise HTTPException(status_code=500, detail="User creation failed.")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user_data.username}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(data={"sub": user_data.username})
    # 数据库记录登录时间
    user_base = await crud.get_user_by_username(user_data.username)
    await crud.update_login_time(user_base)

    return {
        "message": "用户注册成功。",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "is_active": new_user.is_active,
            "is_admin": new_user.is_admin,
        },
        "tokens": {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    }
