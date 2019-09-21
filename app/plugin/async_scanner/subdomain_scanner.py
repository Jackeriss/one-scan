from wafw00f.main import WafW00F
from wafw00f.lib.evillib import oururlparse

from util.http_util import http_client


__plugin__ = "Subdomain Scanner"
SEQUENCE = 2


URL = "https://www.virustotal.com/vtapi/v2/domain/report"
API_KEY = "a0283a2c3d55728300d064874239b5346fb991317e8449fe43c902879d758088"


async def run(url):
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [
        {"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}
    ]
    result_map = {
        "subdomain": {"name": "Subdomain", "sequence": 0, "result": []},
        "domain_siblings": {"name": "Domain Siblings", "sequence": 0, "result": []},
    }

    try:
        params = {"domain": url.netloc, "apikey": API_KEY}
        response = await http_client.get(URL, params=params, format="json")
        result_map["subdomain"]["result"] = (
            response.json_data["subdomain"]
            if response.json_data.get("subdomain")
            else ["Unknown"]
        )
        result_map["domain_siblings"]["result"] = (
            response.json_data["domain_siblings"]
            if response.json_data.get("domain_siblings")
            else ["Unknown"]
        )
    except:
        return error_result

    for result in result_map.values():
        result["result"] = [{"name": item} for item in result["result"]]
    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
