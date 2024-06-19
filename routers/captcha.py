import hashlib
import random
import threading
import uuid
from io import BytesIO

from captcha.image import ImageCaptcha
from fastapi import HTTPException, Form, APIRouter, Depends
from starlette import status
from starlette.requests import Request
from starlette.responses import StreamingResponse
from utils.request_limit import get_rate_limiter

captchaRoute = APIRouter(
    prefix="/captcha",
    tags=["验证码"],
    responses={404: {"description": "Not found"}},
)

# 用于存储验证码的哈希值
captcha_tokens = {}


def generate_captcha_text():
    """
    生成验证码文本。

    这个函数生成一个包含4个字符的验证码，字符可以是数字或大写字母。

    **返回**

    返回一个包含4个字符的验证码文本。
    """
    return ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))

def remove_token(token: str):
    """
    删除指定的验证码标识码。

    这个函数从 `captcha_tokens` 字典中删除指定的验证码标识码。

    **参数**

    - `token`: 需要删除的验证码标识码。

    **返回**

    无返回值。
    """
    captcha_tokens.pop(token, None)


def hash_text(text: str) -> str:
    """
    对指定的文本进行哈希。

    这个函数使用 SHA-256 算法对指定的文本进行哈希。

    **参数**

    - `text`: 需要进行哈希的文本。

    **返回**

    返回哈希后的文本。
    """
    return hashlib.sha256(text.encode()).hexdigest()


@captchaRoute.get("", dependencies=[Depends(get_rate_limiter(max_calls=10, time_span=1))])
async def get_captcha(request: Request):
    """
    生成验证码接口。

    这个接口生成一个新的验证码，并将验证码的哈希值存储在会话中。

    **保护**

    此接口受到请求频率限制，每个客户端在一分钟内最多只能请求10次。

    **参数**

    - `request`: HTTP请求对象。

    **返回**

    返回一个包含验证码的图片。
    """
    # 生成验证码
    image = ImageCaptcha(width=280, height=90)
    captcha_text = generate_captcha_text()
    data = image.generate(captcha_text)
    image_bytes = BytesIO(data.getvalue())
    request.session['captcha'] = hash_text(captcha_text)  # 将验证码文本的哈希值存储在会话中
    return StreamingResponse(image_bytes, media_type="image/png")


@captchaRoute.post("/verify", dependencies=[Depends(get_rate_limiter(max_calls=5, time_span=1))])
async def verify(
        request: Request,
        captcha: str = Form(...)
) -> dict:
    """
    验证验证码接口。

    这个接口接收用户输入的验证码，并与会话中存储的验证码哈希值进行比较。

    **参数**

    - `request`: HTTP请求对象。
    - `captcha`: 用户输入的验证码。

    **返回**

    如果验证码正确，返回一个成功的消息。否则，抛出一个HTTP异常。
    """
    if 'captcha' in request.session and request.session['captcha'] == hash_text(captcha.upper()):
        # 生成鉴权标识码，用于注册接口的验证
        captcha_token = str(uuid.uuid4())
        captcha_tokens[captcha_token] = hash_text(captcha)
        # 设置一个定时器，在5分钟后自动删除这个标识码
        timer = threading.Timer(300, remove_token, args=[captcha_token])
        timer.start()
        del request.session['captcha']  # 验证成功后删除验证码
        return {"status": "success", "code": status.HTTP_200_OK, "message": "验证成功！", "captcha_token": captcha_token}
    else:
        raise HTTPException(status_code=400, detail="验证码错误")
