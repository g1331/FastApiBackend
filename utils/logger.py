import datetime
import logging
from pathlib import Path

from loguru import logger


# 定义 FastAPI 的日志处理器，将其输出重定向到 Loguru
class LoguruHandler(logging.Handler):

    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_globals['__name__'] == logging.__name__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())

    @staticmethod
    def handle_uvicorn_log():
        # 移除已有的uvicorn日志处理器
        logging.getLogger("uvicorn").handlers = []
        # 添加自定义的Loguru处理器
        logging.getLogger("uvicorn.access").handlers = [LoguruHandler()]
        logging.getLogger("uvicorn.error").handlers = [LoguruHandler()]
        logging.getLogger("uvicorn.asgi").handlers = [LoguruHandler()]


class SystemLogger(object):
    APPLogStr = "App"
    APILogStr = "API"
    DatabaseLogStr = "DB"
    AuthLogStr = "Auth"
    UserActionStr = "UserAction"
    SystemActionStr = "SystemAction"
    MailLogStr = "Mail"
    ConfigLogStr = "Config"

    _instance = None
    _configured = False

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SystemLogger, cls).__new__(cls)
        return cls._instance

    def __init__(self, global_config: ConfigLogStr):
        if not self._configured:
            self.configure(global_config)

    def configure(self, global_config: ConfigLogStr):
        # 配置 Loguru
        logger.add(
            Path.cwd() / "logs" / "{time:YYYY-MM-DD}" / "debug.log",
            level="DEBUG",
            retention=f"{global_config.log.debug_log_save_days} days",
            encoding="utf-8",
            rotation=datetime.time(),
        )
        logger.add(
            Path.cwd() / "logs" / "{time:YYYY-MM-DD}" / "common.log",
            level="INFO",
            retention=f"{global_config.log.common_log_save_days} days",
            encoding="utf-8",
            rotation=datetime.time(),
        )
        logger.add(
            Path.cwd() / "logs" / "{time:YYYY-MM-DD}" / "error.log",
            level="ERROR",
            retention=f"{global_config.log.error_log_save_days} days",
            encoding="utf-8",
            rotation=datetime.time(),
        )
        logger.success(SystemLogger.config_msg("application logger configured"))
        self._configured = True

    @staticmethod
    def app_msg(msg: str):
        return f"|{SystemLogger.APPLogStr}| {msg}"

    @staticmethod
    def api_msg(msg: str):
        return f"|{SystemLogger.APILogStr}| {msg}"

    @staticmethod
    def db_msg(msg: str):
        return f"|{SystemLogger.DatabaseLogStr}| {msg}"

    @staticmethod
    def auth_msg(msg: str):
        return f"|{SystemLogger.AuthLogStr}| {msg}"

    @staticmethod
    def user_action_msg(msg: str):
        return f"|{SystemLogger.UserActionStr}| {msg}"

    @staticmethod
    def system_action_msg(msg: str):
        return f"|{SystemLogger.SystemActionStr}| {msg}"

    @staticmethod
    def mail_msg(msg: str):
        return f"|{SystemLogger.MailLogStr}| {msg}"

    @staticmethod
    def config_msg(msg: str):
        return f"|{SystemLogger.ConfigLogStr}| {msg}"
