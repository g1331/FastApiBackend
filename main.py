import logging
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from sqlalchemy.exc import InternalError, ProgrammingError
from starlette.middleware.sessions import SessionMiddleware

import schemas
from database import orm, crud
from routers.captcha import captchaRoute
from routers.token import tokenRoute
from routers.user import userRoute
from utils.logger import SystemLogger

load_dotenv()  # 加载.env文件中的环境变量


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
    _app.include_router(
        router=userRoute,
        prefix="/v1"
    )
    _app.include_router(
        router=tokenRoute,
        prefix="/v1"
    )
    _app.include_router(
        router=captchaRoute,
        prefix="/v1"
    )
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

    logger.info("Application started")

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
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))  # type: ignore

if __name__ == "__main__":
    if os.getenv("DEBUG_MODE") == "True":
        uvicorn.run(
            "main:app",
            host=os.getenv("APP_HOST"), port=int(os.getenv("APP_PORT")),
            reload=True, log_level="debug"
        )
    else:
        uvicorn.run(
            "main:app",
            host=os.getenv("APP_HOST"), port=int(os.getenv("APP_PORT")),
            log_level="info"
        )
