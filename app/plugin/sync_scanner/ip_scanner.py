import re

import dns.resolver
from ipwhois import IPWhois

from app.constant.constant import UNKNOWN


__plugin__ = "IP Scanner"
SEQUENCE = 0


RESOLVER_NAMESERVERS = ["223.5.5.5", "1.1.1.1", "114.114.114.114"]
RESOLVER_TIMEOUT = 2
RESOLVER_LIFETIME = 8


def run(url):
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": {}}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [{"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}]
    host_ip_list = []

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = RESOLVER_NAMESERVERS
        resolver.timeout = RESOLVER_TIMEOUT
        resolver.lifetime = RESOLVER_LIFETIME
        answers = resolver.query(
            url.netloc, rdtype=dns.rdatatype.A, raise_on_no_answer=False
        )
        for answer in answers:
            host_ip_list.append(answer.to_text())
    except dns.resolver.Timeout:
        error_result["result"][0]["result"] = f"{__plugin__}scan timeout"
        return error_result
    except:
        return error_result

    host_ip_list = filter(lambda x: re.match(r"\d+\.\d+\.\d+\.\d+", x), host_ip_list)

    if not host_ip_list:
        return error_result

    for host_ip in host_ip_list:
        result_map = {
            "asn_code": {"name": "ASN code", "sequence": 0, "result": []},
            "asn_description": {"name": "ASN description", "sequence": 1, "result": []},
            "asn_country_code": {"name": "ASN country code", "sequence": 2, "result": []},
            "asn_cidr": {"name": "ASN CIDR", "sequence": 3, "result": []},
            "asn_registry": {"name": "ASN registry", "sequence": 4, "result": []},
            "asn_date": {"name": "ASN date", "sequence": 5, "result": []},
            "ip_version": {"name": "IP version", "sequence": 6, "result": []},
        }
        try:
            ip_whois = IPWhois(host_ip)
            host_ip_result = ip_whois.lookup_rdap()
        except:
            return error_result
        asn_code = host_ip_result.get("asn")
        result_map["asn_code"]["result"].append(
            {
                "name": asn_code if asn_code else UNKNOWN,
                "url": f"https://whois.ipip.net/AS{asn_code}" if asn_code else None,
            }
        )
        asn_description = host_ip_result.get("asn_description")
        result_map["asn_description"]["result"].append(
            {
                "name": asn_description if asn_description else UNKNOWN,
                "url": f"https://whois.ipip.net/AS{asn_code}" if asn_code else None,
            }
        )
        asn_country_code = host_ip_result.get("asn_country_code")
        result_map["asn_country_code"]["result"].append(
            {
                "name": asn_country_code if asn_country_code else UNKNOWN,
                "url": f"https://whois.ipip.net/countries/{asn_country_code}"
                if asn_country_code
                else None,
            }
        )
        asn_cidr = host_ip_result.get("asn_cidr")
        result_map["asn_cidr"]["result"].append(
            {
                "name": asn_cidr if asn_cidr else UNKNOWN,
                "url": f"https://whois.ipip.net/AS{asn_code}/{asn_cidr}"
                if asn_code and asn_cidr
                else None,
            }
        )
        result_map["asn_registry"]["result"].append(
            {"name": host_ip_result.get("asn_registry", UNKNOWN)}
        )
        result_map["asn_date"]["result"].append(
            {"name": host_ip_result.get("asn_date", UNKNOWN)}
        )
        result_map["ip_version"]["result"].append(
            {"name": host_ip_result.get("network", {}).get("ip_version", UNKNOWN)}
        )
        scan_result["result"][host_ip] = sorted(
            [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
        )

    return scan_result
