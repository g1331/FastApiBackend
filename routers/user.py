import random
import re
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi_mail import MessageSchema, FastMail
from loguru import logger
from starlette import status
from starlette.responses import JSONResponse

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
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "Not found",
            "content": {"application/json": {"example": {"detail": "Not found"}}},
        }
    },
)


def validate_password(password: str) -> bool:
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


def validate_username(username: str) -> bool:
    """
    验证用户名是否符合条件。

    此函数验证用户名是否符合以下条件：

    1. 长度在4到15个字符之间。
    2. 仅包含中英文、数字、下划线。
    3. 如果包含中文字符，则不必包含英文或数字。
    4. 如果不包含中文字符，则必须同时包含英文和数字。

    **参数**:

    - username (str): 需要验证的用户名。

    **返回**:

    - bool: 如果用户名符合条件，返回True，否则返回False。
    """
    # 用户名长度校验
    if not (4 <= len(username) <= 15):
        return False

    # 特殊字符校验（仅允许中英文、数字、下划线）
    if not re.match(r'^[\u4e00-\u9fa5_a-zA-Z0-9]+$', username):
        return False

    # 包含中文字符的情况
    if re.search(r'[\u4e00-\u9fa5]', username):
        return True

    # 不包含中文字符的情况，必须同时包含英文和数字
    if re.search(r'[a-zA-Z]', username) and re.search(r'[0-9]', username):
        return True

    return False


@userRoute.post(
    "/register",
    dependencies=[Depends(get_rate_limiter(max_calls=3, time_span=1))],
    response_model=schemas.user.RegisterResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {
                        "无效用户名": {
                            "detail": "用户名长度必须在 4~15 之间，且仅包含中英文和数字。"
                        },
                        "无效密码": {
                            "detail": "密码长度必须在 8~20 之间，且至少包含一个大写字母、一个小写字母和一个数字。"
                        },
                        "无效验证码": {
                            "detail": "验证码无效。"
                        }
                    }
                }
            },
        },
        status.HTTP_409_CONFLICT: {
            "description": "Conflict",
            "content": {
                "application/json": {"example": {"detail": "此用户名已被注册！"}}
            },
        },
        status.HTTP_429_TOO_MANY_REQUESTS: {
            "description": "Too Many Requests",
            "content": {
                "application/json": {"example": {"detail": "验证码已发送，请检查您的邮箱。"}}
            },
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal Server Error",
            "content": {
                "application/json": {"example": {"detail": "验证码发送失败！"}}
            },
        },
    }
)
async def request_verification(
        user: schemas.user.UserCreate,
        captcha_token: str,
        mail_service: FastMail = Depends(verification_cache.get_mail_client),
) -> JSONResponse:
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
    # 检查用户名是否符合条件
    if not validate_username(user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名长度必须在 4~15 之间，且仅包含中英文和数字。"
        )

    # 检查用户名是否已存在
    existing_user = await crud.get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(status_code=409, detail="此用户名已被注册！")

    # 检查密码是否符合条件
    if not validate_password(user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="密码长度必须在 8~20 之间，且至少包含一个大写字母、一个小写字母和一个数字。"
        )

    # 在发送之前，检查 register_tokens 中是否存在验证码的哈希值
    if captcha_token not in captcha_tokens:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码无效。")
    # 删除缓存
    captcha_tokens.pop(captcha_token, None)

    # 检查是否已经发送过验证码并且验证码还在有效期内
    if verification_cache.is_code_active(user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="验证码已发送，请检查您的邮箱。")

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
        logger.error(SystemLogger.mail_msg(f"无法发送验证码，服务器内部错误！详细信息：{e}"))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="验证码发送失败！")
    else:
        # 在成功发送邮件后添加日志记录
        logger.info(SystemLogger.mail_msg(f"验证码 {code} 已发送至 {user.email}"))
    verification_cache.set_code(user.email, code)
    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "验证码已发送至您的邮箱。"})


@userRoute.post(
    "/verify-and-create",
    dependencies=[Depends(get_rate_limiter(max_calls=3, time_span=1))],
    response_model=schemas.user.VerifyResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {
                        "验证码已过期": {"detail": "验证码已过期。"},
                        "验证码无效": {"detail": "验证码无效。"},
                        "验证码错误": {"detail": "验证码错误。"}
                    }
                }
            },
        },
        status.HTTP_409_CONFLICT: {
            "description": "Conflict",
            "content": {
                "application/json": {"example": {"detail": "用户已被注册"}}
            },
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "description": "Internal Server Error",
            "content": {
                "application/json": {"example": {"detail": "User creation failed."}}
            },
        },
    }
)
async def verify_and_create(
        request: schemas.user.VerifyRequest,
        user_data: schemas.user.UserCreate,
) -> JSONResponse:
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码已过期。")
    elif stored_code is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码无效。")
    elif stored_code == request.code:
        # 防止反复创建
        existing_user = await crud.get_user_by_username(user_data.username)
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="用户已被注册")
        # 验证成功，调用 create_user 创建新用户
        new_user = await crud.create_user(user_data)
        if new_user is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User creation failed.")
        # 删除验证码
        verification_cache.delete_code(request.email)
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "message": "用户注册成功。",
                "user": {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "is_active": new_user.is_active,
                    "is_admin": new_user.is_admin,
                }
            }
        )
    else:
        verification_cache.delete_code(user_data.email)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="验证码错误。")


@userRoute.get(
    "/me",
    response_model=schemas.user.User,
    responses={
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {
                "application/json": {"example": {"detail": "已禁用的用户"}}
            }
        }
    }
)
async def read_users_me(current_user: schemas.user.User = Depends(get_current_active_user)):
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


@userRoute.get(
    "",
    response_model=List[schemas.user.User],
    responses={
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {
                "application/json": {"example": {"detail": "权限不足！只有管理员可以访问此接口"}}
            }
        }
    }
)
async def read_users(
        skip: int = 0, limit: int = 10,
        current_user: schemas.user.User = Depends(get_current_active_admin)
):
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
    logger.debug(SystemLogger.user_action_msg(f"管理员 {current_user.username} 请求获取用户列表。"))
    return await crud.get_users(skip=skip, limit=limit)


@userRoute.get(
    "/{user_id}",
    response_model=schemas.user.User,
    responses={
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {
                "application/json": {"example": {"detail": "权限不足！只有管理员可以访问此接口"}}
            }
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Not Found",
            "content": {"application/json": {"example": {"detail": "User not found"}}}
        }
    }
)
async def read_user(user_id: int, current_user: schemas.user.User = Depends(get_current_active_admin)):
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
    logger.debug(SystemLogger.user_action_msg(f"管理员 {current_user.username} 请求获取用户 {user_id} 的信息。"))
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@userRoute.put(
    "/{user_id}",
    response_model=schemas.user.User,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "description": "Bad Request",
            "content": {"application/json": {"example": {"detail": "Inactive user"}}}
        },
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {
                "application/json": {"example": {
                    "detail": "Cannot change the username of the admin user"
                }}
            }
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Not Found",
            "content": {"application/json": {"example": {"detail": "User not found"}}}
        }
    }
)
async def update_user(
        user_id: int, user_update: schemas.user.UserUpdate,
        current_user: schemas.user.User = Depends(get_current_active_admin)
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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.username == "admin" and user_update.username != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Cannot change the username of the admin user")
    return await crud.update_user(user_id, user_update)


@userRoute.delete(
    "/{user_id}",
    response_model=schemas.user.User,
    responses={
        status.HTTP_403_FORBIDDEN: {
            "description": "Forbidden",
            "content": {
                "application/json": {"example": {"detail": "Only the admin user can delete other administrators"}}
            }
        },
        status.HTTP_404_NOT_FOUND: {
            "description": "Not Found",
            "content": {"application/json": {"example": {"detail": "User not found"}}}
        }
    }
)
async def delete_user(user_id: int, current_user: schemas.user.User = Depends(get_current_active_admin)):
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_admin and user.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the admin user can delete other administrators"
        )
    if user.is_admin and user.username == "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot delete admin user")
    logger.debug(SystemLogger.user_action_msg(f"管理员 {current_user.username} 请求删除用户 {user_id} 的信息。"))
    return await crud.delete_user(user_id)
