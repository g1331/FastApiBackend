import logging
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import List, Dict

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from sqlalchemy.exc import InternalError, ProgrammingError

import crud
import schemas
from auth import get_current_active_user, get_current_active_admin
from database import orm
from utils import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, create_refresh_token

from logger import SystemLogger


# 定义 FastAPI 的日志处理器，将其输出重定向到 Loguru
class LoguruHandler(logging.Handler):
    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except KeyError:
            level = record.levelno
        logger.log(level, record.getMessage())


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 配置 Loguru
    logger.remove()  # 移除默认的日志处理器
    logger.add(sys.stdout, format="{time} {level} {message}", filter="my_module", level="INFO")

    # 获取 FastAPI 的日志记录器
    uvicorn_logger = logging.getLogger("uvicorn")

    # 清空 FastAPI 日志记录器的处理器
    uvicorn_logger.handlers = []

    # 添加 Loguru 处理器到 FastAPI 日志记录器
    uvicorn_logger.addHandler(LoguruHandler())

    # 初始化检查
    try:
        _ = await orm.init_check()
    except (AttributeError, InternalError, ProgrammingError):
        _ = await orm.create_all()

    # 在应用程序启动时运行的代码
    admin = await crud.get_user_by_username("admin")
    if not admin:
        import random
        import string
        admin_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        admin_user = schemas.UserCreate(username="admin", password=admin_password)
        await crud.create_user(admin_user, is_admin=True)
        SystemLogger.info(SystemLogger.DbLogger, f"Admin user created with password: {admin_password}")

    yield  # 在这里分隔启动和关闭事件

    # 在应用程序关闭时运行的代码
    await orm.close()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,  # type: ignore
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate):
    db_user = await crud.get_user_by_username(user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    user_info = await crud.create_user(user)
    return {
        "id": user_info.id,
        "username": user_info.username,
        "email": user_info.email,
        "is_active": user_info.is_active,
        "is_admin": user_info.is_admin,
        "avatar": user_info.avatar,
        "created_at": user_info.created_at,
        "updated_at": user_info.updated_at,
        "login_count": user_info.login_count,
        "last_login": user_info.last_login
    }


@app.post("/token", response_model=Dict[str, str])
async def login_for_access_token(
        request: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
):
    user = await crud.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    refresh_token = create_refresh_token(data={"sub": user.username})
    client_ip = request.client.host  # 获取客户端的IP地址
    SystemLogger.info(
        SystemLogger.UserAction,
        f"User {user.username} logged in，IP: {client_ip}"  # 在日志中记录IP地址
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/token/refresh", response_model=Dict[str, str])
async def refresh_access_token(token_request: schemas.TokenRequest):
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
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/", response_model=List[schemas.User])
async def read_users(skip: int = 0, limit: int = 10, current_user: schemas.User = Depends(get_current_active_admin)):
    return await crud.get_users(skip=skip, limit=limit)


@app.get("/users/{user_id}", response_model=schemas.User)
async def read_user(user_id: int, current_user: schemas.User = Depends(get_current_active_admin)):
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.put("/users/{user_id}", response_model=schemas.User)
async def update_user(user_id: int, user_update: schemas.UserUpdate,
                      current_user: schemas.User = Depends(get_current_active_admin)):
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin" and user_update.username != "admin":
        raise HTTPException(status_code=403, detail="Cannot change the username of the admin user")
    return await crud.update_user(user_id, user_update)


@app.delete("/users/{user_id}", response_model=schemas.User)
async def delete_user(user_id: int, current_user: schemas.User = Depends(get_current_active_admin)):
    user = await crud.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin and user.username != "admin":
        raise HTTPException(status_code=403, detail="Only the admin user can delete other administrators")
    if user.is_admin and user.username == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete admin user")
    return await crud.delete_user(user_id)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True, log_level=None)
