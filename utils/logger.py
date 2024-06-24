import logging
import sys

from loguru import logger


# 定义 FastAPI 的日志处理器，将其输出重定向到 Loguru
class LoguruHandler(logging.Handler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # 配置 Loguru
        logger.add(sys.stdout, format="{time} {level} {message}", filter="my_module", level="INFO")

    def emit(self, record):
        try:
            level = logger.level(record.levelname).name
        except KeyError:
            level = record.levelno
        logger.log(level, record.getMessage())


class SystemLogger(logging.Handler):
    APILogger = "API"
    DbLogger = "Database"
    AuthLogger = "Authentication"
    UserAction = "UserAction"
    SystemAction = "SystemAction"
    Mail = "Mail"
    Config = "Config"

    @staticmethod
    def api_msg(msg: str):
        return f"|{SystemLogger.APILogger}| {msg}"

    @staticmethod
    def db_msg(msg: str):
        return f"|{SystemLogger.DbLogger}| {msg}"

    @staticmethod
    def auth_msg(msg: str):
        return f"|{SystemLogger.AuthLogger}| {msg}"

    @staticmethod
    def user_action_msg(msg: str):
        return f"|{SystemLogger.UserAction}| {msg}"

    @staticmethod
    def system_action_msg(msg: str):
        return f"|{SystemLogger.SystemAction}| {msg}"

    @staticmethod
    def mail_msg(msg: str):
        return f"|{SystemLogger.Mail}| {msg}"

    @staticmethod
    def config_msg(msg: str):
        return f"|{SystemLogger.Config}| {msg}"


SystemLogger = SystemLogger()
