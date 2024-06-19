import random
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi_mail import MessageSchema, FastMail

import schemas
from database import crud
from routers.captcha import captcha_tokens
from utils.auth import get_current_active_admin, get_current_active_user
from utils.email_verify import verification_cache
from utils.logger import SystemLogger
from utils.request_limit import get_rate_limiter

userRoute = APIRouter(
    prefix="/users",
    tags=["用户"],
    responses={404: {"description": "Not found"}},
)


def validate_password(password: str):
    """
    验证密码是否符合条件。

    这个函数检查密码长度是否在8~20之间，且至少包含一个大写字母、一个小写字母和一个数字。

    **参数**

    - `password`: 需要验证的密码。

    **返回**

    如果密码符合条件，返回 True。否则，返回 False。
    """
    if len(password) < 8 or len(password) > 20:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    return True


@userRoute.post("/register", dependencies=[Depends(get_rate_limiter(max_calls=3, time_span=1))])
async def request_verification(
        user: schemas.UserCreate,
        captcha_token: str,
        mail_service: FastMail = Depends(verification_cache.get_mail_client),
) -> dict:
    """
    用户注册接口。

    这个接口接收一个用户的注册信息，包括用户名、邮箱和密码。如果用户名未被注册，系统将会向用户的邮箱发送一个验证码。

    **保护**

    此接口受到请求频率限制，每个客户端在一分钟内最多只能请求三次。

    **参数**

    - `user`: 用户的注册信息，包括：
        - `username`: 用户名，必须是唯一的。
        - `email`: 用户的邮箱地址，用于接收验证码。
        - `password`: 用户的密码。
    - `captcha_token`: 校验是否通过图像验证码。

    **返回**

    如果注册信息有效，系统将会向用户的邮箱发送一个验证码，并返回一个消息："验证码已发送至您的邮箱。"
    """
    # 检查用户名是否已存在
    existing_user = await crud.get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(status_code=409, detail="此用户名已被注册！")

    # 检查密码是否符合条件
    if not validate_password(user.password):
        raise HTTPException(status_code=400,
                            detail="密码长度必须在 8~20 之间，且至少包含一个大写字母、一个小写字母和一个数字。")

    # 在发送之前，检查 register_tokens 中是否存在验证码的哈希值
    if captcha_token not in captcha_tokens:
        raise HTTPException(status_code=400, detail="验证码无效。")
    # 删除缓存
    captcha_tokens.pop(captcha_token, None)

    # 检查是否已经发送过验证码并且验证码还在有效期内
    if verification_cache.is_code_active(user.email):
        raise HTTPException(
            status_code=429, detail="验证码已发送，请检查您的邮箱。")

    # 发送验证码
    code = str(random.randint(100000, 999999))
    template = r"""
    <html>
    <head>
        <title>用户注册验证码</title>
    </head>
    <body>
        <div>
            <h1>您的验证码是 {code}</h1>
            <p>请在注册页面中输入此验证码以完成注册。有效期为 5 分钟。</p>
        </div>
    </body>
    </html>
    """
    try:
        message = MessageSchema(
            subject="用户注册验证码",
            recipients=[user.email],
            body=template.format(code=code),
            subtype="html"
        )
        await mail_service.send_message(message)
    except Exception as e:
        # 打印异常的详细信息
        SystemLogger.error(SystemLogger.Mail, f"无法发送验证码，服务器内部错误！详细信息：{e}")
        raise HTTPException(status_code=500, detail="验证码发送失败！")
    else:
        # 在成功发送邮件后添加日志记录
        SystemLogger.info(SystemLogger.Mail, f"验证码 {code} 已发送至 {user.email}")
    verification_cache.set_code(user.email, code)
    return {"message": "验证码已发送至您的邮箱。"}


@userRoute.post("/verify-and-create", dependencies=[Depends(get_rate_limiter(max_calls=3, time_span=1))])
async def verify_and_create(
        request: schemas.VerifyRequest,
        user_data: schemas.UserCreate,
) -> dict:
    """
    验证并创建用户接口。

    这个接口接收一个验证码和用户的注册信息，包括用户名、邮箱和密码。如果验证码正确，系统将会创建一个新的用户。

    **保护**

    此接口受到请求频率限制，每个客户端在一分钟内最多只能请求三次。

    **参数**

    - `request`: 包含验证码的请求，包括：
        - `email`: 用户的邮箱地址，用于验证验证码。
        - `code`: 用户收到的验证码。
    - `user_data`: 用户的注册信息，包括：
        - `username`: 用户名，必须是唯一的。
        - `email`: 用户的邮箱地址。
        - `password`: 用户的密码。

    **返回**

    如果验证码正确，系统将会创建一个新的用户，并返回用户的信息和一个消息："用户注册成功。"
    """
    stored_code = verification_cache.get_code(request.email)
    if stored_code == "EXPIRED":
        raise HTTPException(status_code=400, detail="验证码已过期。")
    elif stored_code is None:
        raise HTTPException(status_code=400, detail="验证码无效。")
    elif stored_code == request.code:
        # 防止反复创建
        existing_user = await crud.get_user_by_username(user_data.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="用户已被注册")
        # 验证成功，调用 create_user 创建新用户
        new_user = await crud.create_user(user_data)
        if new_user is None:
            raise HTTPException(status_code=500, detail="User creation failed.")
        # 删除验证码
        verification_cache.delete_code(request.email)
        return {
            "message": "用户注册成功。",
            "user": {
                "username": new_user.username,
                "email": new_user.email,
                "is_active": new_user.is_active,
                "is_admin": new_user.is_admin,
            }
        }
    else:
        verification_cache.delete_code(user_data.email)
        raise HTTPException(status_code=400, detail="验证码错误。")


@userRoute.get("/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_active_user)):
    """
    获取当前活跃用户的接口。

    这个接口返回当前活跃用户的信息。

    **保护**

    此接口需要用户已经通过身份验证并且账户处于活跃状态。

    **参数**

    - `current_user`: 当前活跃用户，由 `get_current_active_user` 函数提供。

    **返回**

    返回当前活跃用户的信息。
    """
    return current_user


@userRoute.get("", response_model=List[schemas.User])
async def read_users(skip: int = 0, limit: int = 10, current_user: schemas.User = Depends(get_current_active_admin)):
    """
    获取用户列表接口。

    这个接口返回用户列表，可以通过 `skip` 和 `limit` 参数来控制返回的用户数量和起始位置。

    **保护**

    此接口需要管理员权限。

    **参数**

    - `skip`: 跳过的用户数量，用于分页。
    - `limit`: 返回的最大用户数量，用于分页。
    - `current_user`: 当前管理员用户，由 `get_current_active_admin` 函数提供。

    **返回**

    返回用户列表。
    """
    SystemLogger.debug(SystemLogger.UserAction, f"管理员 {current_user.username} 请求获取用户列表。")
    return await crud.get_users(skip=skip, limit=limit)


@userRoute.get("/{user_id}", response_model=schemas.User)
async def read_user(user_id: int, current_user: schemas.User = Depends(get_current_active_admin)):
    """
    获取特定用户接口。

    这个接口返回特定用户的信息。

    **保护**

    此接口需要管理员权限。

    **参数**

    - `user_id`: 需要获取信息的用户的 ID。
    - `current_user`: 当前管理员用户，由 `get_current_active_admin` 函数提供。

    **返回**

    如果用户存在，返回用户的信息。如果用户不存在，返回 404 错误。
    """
    SystemLogger.debug(SystemLogger.UserAction, f"管理员 {current_user.username} 请求获取用户 {user_id} 的信息。")
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@userRoute.put("/{user_id}", response_model=schemas.User)
async def update_user(
        user_id: int, user_update: schemas.UserUpdate,
        current_user: schemas.User = Depends(get_current_active_admin)
):
    """
    更新用户接口。

    这个接口接收一个用户的更新信息和用户的 ID。如果当前用户是管理员并且活跃，系统将会更新指定用户的信息。

    **保护**

    此接口需要管理员权限。

    **参数**

    - `user_id`: 需要更新信息的用户的 ID。
    - `user_update`: 用户的更新信息。
    - `current_user`: 当前管理员用户，由 `get_current_active_admin` 函数提供。

    **返回**

    如果用户存在，返回更新后的用户信息。如果用户不存在，返回 404 错误。
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin" and user_update.username != "admin":
        raise HTTPException(status_code=403, detail="Cannot change the username of the admin user")
    return await crud.update_user(user_id, user_update)


@userRoute.delete("/{user_id}", response_model=schemas.User)
async def delete_user(user_id: int, current_user: schemas.User = Depends(get_current_active_admin)):
    """
    删除用户接口。

    这个接口接收一个用户的 ID。如果当前用户是管理员并且活跃，系统将会删除指定用户。

    **保护**

    此接口需要管理员权限。

    **参数**

    - `user_id`: 需要删除的用户的 ID。
    - `current_user`: 当前管理员用户，由 `get_current_active_admin` 函数提供。

    **返回**

    如果用户存在，返回被删除的用户信息。如果用户不存在，返回 404 错误。
    """
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin and user.username != "admin":
        raise HTTPException(status_code=403, detail="Only the admin user can delete other administrators")
    if user.is_admin and user.username == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete admin user")
    SystemLogger.debug(SystemLogger.UserAction, f"管理员 {current_user.username} 请求删除用户 {user_id} 的信息。")
    return await crud.delete_user(user_id)
