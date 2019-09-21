import re

import dns.resolver
import tldextract

from app.plugin.data.dns_provider import DNS_PROVIDER


__plugin__ = "DNS Scanner"
SEQUENCE = 1


RESOLVER_NAMESERVERS = ["223.5.5.5", "1.1.1.1", "114.114.114.114"]
RESOLVER_TIMEOUT = 2
RESOLVER_LIFETIME = 8


def run(url):
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [
        {"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}
    ]
    result_map = {
        "providers": {"name": "DNS providers", "sequence": 0, "result": []},
        "ns_server": {"name": "NS servers", "sequence": 1, "result": []},
    }
    providers = []

    try:
        registered_domain = tldextract.extract(url.netloc).registered_domain
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = RESOLVER_NAMESERVERS
        resolver.timeout = RESOLVER_TIMEOUT
        resolver.lifetime = RESOLVER_LIFETIME
        answers = resolver.query(registered_domain, rdtype=dns.rdatatype.NS)
        for answer in answers:
            result_map["ns_server"]["result"].append(answer.to_text())
    except dns.resolver.Timeout:
        error_result["result"][0]["result"] = f"{__plugin__} scan timeout"
        return error_result
    except:
        return error_result

    for ns_server in result_map["ns_server"]["result"]:
        for dns_provider in DNS_PROVIDER:
            if re.search(f"\\.{dns_provider}", ns_server):
                providers.append(DNS_PROVIDER[dns_provider])
    result_map["providers"]["result"] = list(set(providers)) if providers else ["Unknown"]
    for result in result_map.values():
        result["result"] = [{"name": item} for item in result["result"]]
    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
