import time
from urllib.parse import urlsplit

import aiotask_context

from app.util.time_util import timeout_log
from app.util.cache_util import local_cache
from app.util.plugin_util import get_plugins
from app.util.thread_pool_util import ThreadPool
from app.config.constant import PluginType


ASYNC_SCANNERS = get_plugins(PluginType.ASYNC_SCANNER)
SYNC_SCANNERS = get_plugins(PluginType.SYNC_SCANNER)


class ScannerService(object):

    @classmethod
    @timeout_log(timeout=60, tag="SCAN")
    @local_cache(expire=3600)
    async def scan(cls, url):
        scan_report = []
        url_info = urlsplit(url)
        for async_scanner in ASYNC_SCANNERS:
            scan_report.append(await ASYNC_SCANNERS[async_scanner](url_info))
        for sync_scanner in SYNC_SCANNERS:
            scan_report.append(await ThreadPool.async_func(SYNC_SCANNERS[sync_scanner], url_info))
        scan_report.sort(key=lambda x: x.get("sequence", 0))
        return scan_report
