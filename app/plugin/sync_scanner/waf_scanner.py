from wafw00f.main import WafW00F
from wafw00f.lib.evillib import oururlparse


__plugin__ = "WAF Scanner"
SEQUENCE = 6


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
    error_result["result"] = [{"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}]
    result_map = {"waf": {"name": "WAF Provider", "sequence": 0, "result": []}}

    try:
        hostname, port, path, _, ssl = oururlparse(url.geturl())
        if not hostname:
            return error_result
        wafw00f_scanner = WafW00F(hostname, port=port, ssl=ssl, path=path)
        result_map["waf"]["result"] = wafw00f_scanner.identwaf() or ["Unknown"]
    except:
        return error_result

    for result in result_map.values():
        result["result"] = [{"name": item} for item in result["result"]]
    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
