import time
import urlparse

import aiotask_context

from app.util.time_util import timeout_log
from app.util.cache_util import local_cache
from app.util.config_util import PluginType
from app.util.plugin_util import get_plugins


SCANNERS = get_plugins(PluginType.SCANNER)


class ScannerService(object):

    @classmethod
    @timeout_log(timeout=4, tag="Scanner")
    @local_cache(expire=3600)
    async def scan(cls, url):
        url_info = urlparse.urlsplit(url)
        if not url_info.hostname:
            # TODO: raise error
        for scanner in SCANNERS:
            scan_report[scanner] = await SCANNERS[scanner](url_info)
        return scan_report
