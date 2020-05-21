import time
from urllib.parse import urlsplit

from app.util.time_util import timeout_log
from app.util.cache_util import cache
from app.util.plugin_util import get_plugins
from app.util.thread_pool_util import ThreadPool
from app.constant import constant


ASYNC_SCANNERS = get_plugins(constant.PluginType.ASYNC_SCANNER)
SYNC_SCANNERS = get_plugins(constant.PluginType.SYNC_SCANNER)


class ScannerService(object):
    @classmethod
    @timeout_log(timeout=60, tag="SCAN")
    # @cache(expire=3600)
    async def scan(cls, url):
        scan_report = []
        url_info = urlsplit(url)
        for async_scanner in ASYNC_SCANNERS:
            scan_report.append(await ASYNC_SCANNERS[async_scanner](url_info))
        for sync_scanner in SYNC_SCANNERS:
            scan_report.append(
                await ThreadPool.async_func(SYNC_SCANNERS[sync_scanner], url_info)
            )
        scan_report.sort(key=lambda x: x.get("sequence", 0))
        return scan_report
