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

    @staticmethod
    def info(logger_name, message):
        logger.info(f"|{logger_name}| {message}")

    @staticmethod
    def debug(logger_name, message):
        logger.debug(f"|{logger_name}| {message}")

    @staticmethod
    def error(logger_name, message):
        logger.error(f"|{logger_name}| {message}")

    @staticmethod
    def warning(logger_name, message):
        logger.warning(f"|{logger_name}| {message}")

    @staticmethod
    def success(logger_name, message):
        logger.success(f"|{logger_name}| {message}")

    @staticmethod
    def exception(logger_name, message):
        logger.exception(f"|{logger_name}| {message}")

    @staticmethod
    def critical(logger_name, message):
        logger.critical(f"|{logger_name}| {message}")

    @staticmethod
    def log(logger_name, level, message):
        logger.log(level, f"| {logger_name}| {message}")


SystemLogger = SystemLogger()
