from schema import Optional, Use

from app.model.scanner.service import ScannerService
from app.util.handler_util import BasicHandler


class ScannerHandler(BasicHandler):
    async def get(self):
        params = self.validate_argument({"url": Use(str)})
        scan_report = await ScannerService.scan(**params)
        result = {"scan_report": scan_report}
        return self.success(result)
