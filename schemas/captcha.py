from pydantic import BaseModel, Field


class VerifyResponse(BaseModel):
    code: int = Field(..., title="状态码", description="状态码", examples=[200])
    message: str = Field(..., title="消息", description="消息", examples=["验证成功！"])
    captcha_token: str = Field(..., title="验证码标识", description="验证码标识",
                               examples=["a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p"])
