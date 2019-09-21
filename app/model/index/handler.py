from app.util.handler_util import BasicHandler


class IndexHandler(BasicHandler):
    async def get(self):
        return self.page("index.html")
