# utils/request_limit.py
import os
from datetime import datetime, timedelta
from typing import Dict

from fastapi import HTTPException, status, Request

# 存储客户端的最后调用时间和请求次数
client_call_times: Dict[str, Dict] = {}


async def check_call_frequency(request: Request, max_calls: int, time_span: int):
    """
    检查客户端的调用频率。

    如果客户端在指定的时间跨度内的调用次数超过了最大调用次数，那么抛出一个HTTP异常。

    参数：
        - request: HTTP请求对象。
        - max_calls: 指定时间跨度内的最大调用次数。
        - time_span: 时间跨度（以分钟为单位）。
    """
    # 如果处于调试模式，不进行频率限制
    if os.getenv("DEBUG_MODE") == "True":
        return

    client_ip = request.client.host
    route_path = request.url.path  # 获取请求的路由路径
    key = f"{client_ip}-{route_path}"  # 使用 IP 地址和路由路径作为键

    if key in client_call_times:
        # 如果客户端在过去的指定时间内已经调用过这个路由，那么抛出一个HTTP异常
        if datetime.now() - client_call_times[key]['time'] < timedelta(minutes=time_span) and \
                client_call_times[key]['count'] >= max_calls:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="请求过于频繁，请稍后再试。",
            )
        else:
            client_call_times[key]['count'] += 1
    else:
        client_call_times[key] = {'time': datetime.now(), 'count': 1}


def get_rate_limiter(max_calls: int = 30, time_span: int = 1):
    """
    获取速率限制器。

    这个函数返回一个依赖项，这个依赖项在被调用时会检查客户端的调用频率。

    参数：
        - max_calls: 指定时间跨度内的最大调用次数。
        - time_span: 时间跨度（以分钟为单位）。
    """

    async def _rate_limiter(request: Request):
        return await check_call_frequency(request, max_calls, time_span)

    return _rate_limiter
