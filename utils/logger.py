# loggers.py
from loguru import logger


class SystemLogger:
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
