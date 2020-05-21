from datetime import datetime

import tldextract
import whois

from app.constant.constant import UNKNOWN


__plugin__ = "WHOIS Scanner"
SEQUENCE = 3


def run(url):
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [
        {"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}
    ]
    result_map = {
        "name": {"name": "Name", "sequence": 0, "result": []},
        "registrar": {"name": "Registrar", "sequence": 1, "result": []},
        "emails": {"name": "Emails", "sequence": 2, "result": []},
        "dnssec": {"name": "DNSSEC", "sequence": 3, "result": []},
        "creation_date": {"name": "Creation date (UTC)", "sequence": 4, "result": []},
        "expiration_date": {"name": "Expiration date (UTC)", "sequence": 5, "result": [],},
    }

    try:
        registered_domain = tldextract.extract(url.netloc).registered_domain
        if not registered_domain:
            return error_result
        domain = whois.whois(registered_domain)
        result_map["name"]["result"] = [{"name": domain.name or UNKNOWN}]
        result_map["emails"]["result"] = [{"name": domain.emails or UNKNOWN}]
        result_map["registrar"]["result"] = [{"name": domain.registrar or UNKNOWN}]
        result_map["dnssec"]["result"] = [{"name": domain.dnssec or UNKNOWN}]
        if isinstance(domain.creation_date, list):
            creation_date = domain.creation_date[0]
        else:
            creation_date = domain.creation_date.replace("T", "")
        if isinstance(creation_date, datetime):
            creation_date = datetime.strftime(creation_date, "%Y-%m-%d %H:%M:%S")
        result_map["creation_date"]["result"] = [{"name": creation_date or UNKNOWN}]
        if isinstance(domain.expiration_date, list):
            expiration_date = domain.expiration_date[0]
        else:
            expiration_date = domain.expiration_date.replace("T", "")
        if isinstance(expiration_date, datetime):
            expiration_date = datetime.strftime(expiration_date, "%Y-%m-%d %H:%M:%S")
        result_map["expiration_date"]["result"] = [{"name": expiration_date or UNKNOWN}]
    except:
        scan_result["result"] = [
            {
                "name": "Error",
                "result": [{"name": f"{__plugin__} can't scan this website"}],
            }
        ]
        return scan_result

    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
