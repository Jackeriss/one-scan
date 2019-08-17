""" 扫描 WAF 服务商 """
from wafw00f.main import WafW00F
from wafw00f.lib.evillib import oururlparse


__plugin__ = "WAF 扫描器"
SEQUENCE = 5


def run(url):
    scan_result = {
        "name": __plugin__,
        "sequence": SEQUENCE,
        "result": [],
    }
    error_result = {
        "name": __plugin__,
        "sequence": SEQUENCE,
        "result": [],
    }
    error_result["result"] = [{"name": "错误", "result": f"{__plugin__}无法扫描该网站"}]
    result_map = {"waf": {"name": "WAF 服务商", "sequence": 0, "result": []}}

    try:
        hostname, port, path, _, ssl = oururlparse(url.geturl())
        if not hostname:
            return error_result
        wafw00f_scanner = WafW00F(hostname, port=port, ssl=ssl, path=path)
        result_map["waf"]["result"] = wafw00f_scanner.identwaf()
    except:
        return error_result

    for result in result_map.values():
        result["result"] = [{"name": item} for item in result["result"]]
    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
