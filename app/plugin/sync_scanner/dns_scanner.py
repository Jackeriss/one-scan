""" 扫描 DNS 解析服务商 """
import re

import dns.resolver
import tldextract

from app.plugin.data.dns_provider import DNS_PROVIDER


__plugin__ = "DNS 扫描器"
SEQUENCE = 1


RESOLVER_NAMESERVERS = ["223.5.5.5", "1.1.1.1", "114.114.114.114"]
RESOLVER_TIMEOUT = 2
RESOLVER_LIFETIME = 8


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
    result_map = {"providers": {"name": "DNS 解析服务商", "sequence": 0, "result": []}}
    providers = []
    ns_domain_list = []
    ns_ip_list = []

    try:
        registered_domain = tldextract.extract(url.netloc).registered_domain
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = RESOLVER_NAMESERVERS
        resolver.timeout = RESOLVER_TIMEOUT
        resolver.lifetime = RESOLVER_LIFETIME
        answers = resolver.query(registered_domain, rdtype=dns.rdatatype.NS)
        for answer in answers:
            ns_domain_list.append(answer.to_text())
    except dns.resolver.Timeout:
        error_result["result"][0]["result"] = f"{__plugin__}查询超时"
        return error_result
    except:
        return error_result

    for ns_domain in ns_domain_list:
        added = False
        for dns_provider in DNS_PROVIDER:
            if re.search(f"\\.{dns_provider}", ns_domain):
                providers.append(DNS_PROVIDER[dns_provider])
                added = True
        if not added:
            providers.append(ns_domain)

    providers = list(set(providers))
    result_map["providers"]["result"] = providers
    for result in result_map.values():
        result["result"] = [{"name": item} for item in result["result"]]
    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
