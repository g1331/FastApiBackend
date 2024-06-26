from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger
from sqlalchemy.exc import InternalError, ProgrammingError
from starlette.middleware.sessions import SessionMiddleware

import schemas
from config import global_config
from database import orm, crud
from routers.captcha import captchaRoute
from routers.oauth import oauthRoute
from routers.token import tokenRoute
from routers.user import userRoute
from utils.logger import SystemLogger, LoguruHandler

# 配置日志
system_logger = SystemLogger(global_config)
LoguruHandler.handle_uvicorn_log()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _app.include_router(router=userRoute, prefix="/v1")
    _app.include_router(router=tokenRoute, prefix="/v1")
    _app.include_router(router=captchaRoute, prefix="/v1")
    _app.include_router(router=oauthRoute, prefix="/v1")

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
        admin_user = schemas.user.UserCreate(username="admin", password=admin_password, email="admin@test.com")
        await crud.create_user(admin_user, is_admin=True)
        logger.success(SystemLogger.db_msg(f"Admin user created with password: {admin_password}"))

    logger.success("Application started")

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
app.add_middleware(SessionMiddleware, secret_key=global_config.app.session_secret_key)  # type: ignore


@logger.catch
def start_server():
    if global_config.app.debug_mode == "True":
        uvicorn.run(
            "main:app",
            host=global_config.app.host, port=global_config.app.port,
            reload=True, log_level="debug"
        )
    else:
        uvicorn.run(
            "main:app",
            host=global_config.app.host, port=global_config.app.port,
            log_level="info"
        )


if __name__ == "__main__":
    try:
        logger.info("Application starting")
        start_server()
    except KeyboardInterrupt:
        logger.info("Application stopped")
