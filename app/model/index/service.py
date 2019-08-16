""" 业务逻辑处理 """
import time
import asyncio

import aiotask_context

from app.util.time_util import timeout_log
from app.util.cache_util import local_cache


class IndexService(object):
    """ 包括协程上下文、超时日志和本地缓存等示例 """

    @classmethod
    def calc_area(cls, length, width):
        time.sleep(5)
        area = length * width
        return area

    @classmethod
    # @timeout_log(timeout=4, tag="Index")
    # @local_cache(expire=3)
    async def get_basic_info(cls):
        """ 接口的通用参数可以统一放在 Basic-Info 这个 Header 中
            本地缓存效果：第一次会请求耗时 5 秒左右，3 秒内再次请求会立即返回结果，3 秒后再请求又会耗时 5 秒
            超时日志效果：函数执行超过 4 秒会打印一条超时的错误日志，但是并不会抛异常。
        """
        await asyncio.sleep(5)
        basic_info = aiotask_context.get("handler").basic_info
        return basic_info
