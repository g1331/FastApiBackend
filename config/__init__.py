import os
from typing import Type, Optional, TypeVar

from dotenv import load_dotenv
from loguru import logger

from utils.logger import SystemLogger

load_dotenv()  # 加载.env文件中的环境变量

T = TypeVar("T")


class Config:
    @staticmethod
    def get_env_variable(name: str, type_: Type[T], default: Optional[T] = None) -> T:
        value = os.getenv(name)
        if value is None:
            logger.warning(SystemLogger.config_msg(f"{name} is not set. Using default value: {default}"))
            return default
        return type_(value)

    class App:
        """
        # -----------------------
        # 系统相关配置
        # -----------------------
        # 应用运行的地址
        APP_HOST=localhost
        # 应用运行的端口
        APP_PORT=8000
        # 调试模式开关（开发环境设置为True，生产环境设置为False）
        DEBUG_MODE=False
        # SessionMiddleware的密钥，用于加密会话数据
        SESSION_SECRET_KEY=your-secret-key
        """

        def __init__(self):
            self.host: str = Config.get_env_variable("APP_HOST", str, "localhost")
            self.port: int = Config.get_env_variable("APP_PORT", int, 8000)
            self.debug_mode: bool = Config.get_env_variable(
                "DEBUG_MODE", lambda x: str(x).lower() in ['true', '1', 't', 'y', 'yes'], False)
            self.session_secret_key: str = Config.get_env_variable("SESSION_SECRET_KEY", str)

    class Database:
        """
        # -----------------------
        # 数据库配置 sqlite
        # -----------------------
        # 数据库名称（文件名字）
        DB_NAME=mydatabase
        """

        def __init__(self):
            self.name = Config.get_env_variable("DB_NAME", str, "mydatabase")

        def get_connection_string(self):
            return f"sqlite+aiosqlite:///./{self.name}.db"

    class Email:
        """
        # -----------------------
        # 邮件服务配置
        # -----------------------
        # 邮件账号用户名
        MAIL_USERNAME=your-email@example.com
        # 邮件账号密码
        MAIL_PASSWORD=your-password
        # 发送邮件的邮箱地址
        MAIL_FROM=your-email@example.com
        # 邮件服务器端口
        MAIL_PORT=465
        # 邮件服务器地址
        MAIL_SERVER=smtp.example.com
        # 邮件服务是否启用STARTTLS（通常为True或False）
        MAIL_STARTTLS=False
        # 邮件服务是否启用SSL（通常为True或False，为True时端口请选择465）
        MAIL_SSL_TLS=True
        # 用户注册时邮箱验证的有效期（秒）
        MAIL_EXPIRATION=300
        """

        def __init__(self):
            self.username: str = Config.get_env_variable("MAIL_USERNAME", str, "your-email@example.com")
            self.password: str = Config.get_env_variable("MAIL_PASSWORD", str, "your-password")
            self.from_address: str = Config.get_env_variable("MAIL_FROM", str, "smtp.example.com")
            self.port: int = Config.get_env_variable("MAIL_PORT", int, 465)
            self.server: str = Config.get_env_variable("MAIL_SERVER", str, "smtp.example.com")
            self.starttls: bool = Config.get_env_variable(
                "MAIL_STARTTLS", lambda x: str(x).lower() in ['true', '1', 't', 'y', 'yes'], False)
            self.ssl_tls: bool = Config.get_env_variable(
                "MAIL_SSL_TLS", lambda x: str(x).lower() in ['true', '1', 't', 'y', 'yes'], True)
            self.expiration: int = Config.get_env_variable("MAIL_EXPIRATION", int, 300)

    class Jwt:
        """
        # -----------------------
        # JWT（JSON Web Token）配置
        # -----------------------
        # 该密钥用于签署和验证JWT。在创建JWT时，会使用密钥对其进行签名。当接收到JWT时，可以使用同一密钥来验证签名，以确保JWT没有被篡改。
        JWT_SECRET_KEY=your-jwt-secret-key
        # JWT的有效期（分钟）
        JWT_EXPIRATION_MINUTES=60
        # JWT的刷新Token过期时间（天）
        JWT_REFRESH_EXPIRATION_DAYS=7
        # JWT的算法
        JWT_ALGORITHM=HS256
        """

        def __init__(self):
            self.secret_key: str = Config.get_env_variable("JWT_SECRET_KEY", str, "your-jwt-secret-key")
            self.expiration_minutes: int = Config.get_env_variable("JWT_EXPIRATION_MINUTES", int, 60)
            self.refresh_expiration_days: int = Config.get_env_variable("JWT_REFRESH_EXPIRATION_DAYS", int, 7)
            self.algorithm: str = Config.get_env_variable("JWT_ALGORITHM", str, "HS256")

    class Oauth:
        """
        # -----------------------
        # Oauth Github 配置
        # -----------------------
        # Github OAuth App的Client ID
        GITHUB_CLIENT_ID=your-github-client-id
        # Github OAuth App的Client Secret
        GITHUB_CLIENT_SECRET=your-github-client-secret
        """

        def __init__(self):
            self.github_client_id: str = Config.get_env_variable(
                "GITHUB_CLIENT_ID", str, "your-github-client-id")
            self.github_client_secret: str = Config.get_env_variable(
                "GITHUB_CLIENT_SECRET", str, "your-github-client-secret")

    def __init__(self):
        self.app = self.App()
        self.database = self.Database()
        self.email = self.Email()
        self.jwt = self.Jwt()
        self.oauth = self.Oauth()


global_config = Config()
