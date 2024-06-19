import os
import time
from typing import Union

from dotenv import load_dotenv
from fastapi_mail import FastMail, ConnectionConfig

load_dotenv()  # 加载.env文件中的环境变量


class VerificationCodeCache:
    """
    验证码缓存类。

    这个类用于存储和管理验证码。验证码在一段时间后会过期。

    **属性**

    - `codes`: 存储验证码的字典。键是邮箱地址，值是一个元组，包含验证码和时间戳。
    - `request_counts`: 存储每个邮箱地址的请求次数和最后一次请求的时间。
    - `expiry_time`: 验证码的过期时间（以秒为单位）。
    """
    # 从环境变量读取配置
    mailboxConfiguration = ConnectionConfig(
        MAIL_USERNAME=os.getenv("MAIL_USERNAME", "default-username@example.com"),
        MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", "default-password"),
        MAIL_FROM=os.getenv("MAIL_FROM", "your-email@example.com"),
        MAIL_FROM_NAME=os.getenv("MAIL_FROM_NAME", "Your Name"),
        MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
        MAIL_SERVER=os.getenv("MAIL_SERVER", "smtp.example.com"),
        MAIL_STARTTLS=os.getenv("MAIL_STARTTLS", "True").lower() in ['true', '1', 't', 'y', 'yes'],
        MAIL_SSL_TLS=os.getenv("MAIL_SSL_TLS", "False").lower() in ['true', '1', 't', 'y', 'yes'],
        USE_CREDENTIALS=True,
    )

    def __init__(self, expiry_time=int(os.getenv("MAIL_EXPIRATION"))):
        self.codes = {}
        self.request_counts = {}  # 新增：存储每个邮箱地址的请求次数和最后一次请求的时间
        self.expiry_time = expiry_time

    def set_code(self, email, code) -> None:
        """
        设置验证码。

        这个方法会为指定的邮箱地址设置一个验证码，并记录当前的时间。

        **参数**

        - `email`: 邮箱地址。
        - `code`: 验证码。
        """
        current_time = int(time.time())
        # 检查请求次数
        if email in self.request_counts:
            count, last_time = self.request_counts[email]
            if current_time - last_time < 60 and count >= 3:  # 如果在过去的一分钟内，请求次数已经达到3次
                raise Exception("Too many requests")  # 抛出异常
            else:
                self.request_counts[email] = (count + 1, current_time)  # 增加请求次数，并更新最后一次请求的时间
        else:
            self.request_counts[email] = (1, current_time)  # 如果是第一次请求，设置请求次数为1，并记录请求时间
        # 设置验证码
        self.codes[email] = (code, current_time)

    def get_code(self, email) -> Union[str, None]:
        """
        获取验证码。

        这个方法会返回指定邮箱地址的验证码。如果验证码已经过期，那么会删除验证码，并返回一个特殊的值 "EXPIRED"。

        **参数**

        - `email`: 邮箱地址。

        **返回**

        返回验证码，或者 "EXPIRED"（如果验证码已经过期）。
        """
        if email in self.codes:
            code, timestamp = self.codes[email]
            # 检查验证码是否过期
            if int(time.time()) - timestamp < self.expiry_time:
                return code
            else:
                del self.codes[email]  # 清除过期验证码
                if email in self.request_counts:
                    del self.request_counts[email]  # 重置请求次数
                return "EXPIRED"  # 返回一个特殊的值表示验证码过期
        return None

    def get_mail_client(self) -> FastMail:
        """
        获取邮件客户端。

        这个方法会返回一个 FastMail 对象，可以用于发送邮件。

        **返回**

        返回一个 FastMail 对象。
        """
        return FastMail(self.mailboxConfiguration)

    def delete_code(self, email) -> None:
        """
        删除验证码。

        这个方法会删除指定邮箱地址的验证码。

        **参数**

        - `email`: 邮箱地址。
        """
        if email in self.codes:
            del self.codes[email]

    def is_code_active(self, email) -> bool:
        """
        检查验证码是否有效。

        这个方法会检查指定邮箱地址的验证码是否还在有效期内。

        **参数**

        - `email`: 邮箱地址。

        **返回**

        如果验证码还在有效期内，返回 True，否则返回 False。
        """
        if email in self.codes:
            _, timestamp = self.codes[email]
            # 检查验证码是否过期
            if int(time.time()) - timestamp < self.expiry_time:
                return True
        return False


# 实例化验证码缓存
verification_cache = VerificationCodeCache()
