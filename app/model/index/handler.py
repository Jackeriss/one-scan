""" 仅做参数接收和校验，业务逻辑写在 service.py """
import logging

from schema import Optional, Use

from app.model.index.service import IndexService
from app.util.handler_util import BasicHandler


class IndexHandler(BasicHandler):
    """ handler 示例 """
    
    def get(self):
        result = {
            "title": "你好",
            "name": "World"
        }
        return self.success(result)
    
    async def post(self):
        params = self.validate_argument({
            Optional("length", default=3): Use(int),
            Optional("width", default=5): Use(int)
        })
        area = IndexService.calc_area(length=params["length"], width=params["width"])
        basic_info = await IndexService.get_basic_info()
        result = {
            "area": area,
            "Basic-Info": basic_info
        }
        return self.success(result)


