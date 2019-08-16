import tldextract
import whois


__plugin__ = "WHOIS 扫描器"
SEQUENCE = 5


NOT_FOUND = "未检测到"


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
    result_map = {
        "name": {"name": "注册者", "sequence": 0, "result": []},
        "emails": {"name": "邮箱", "sequence": 1, "result": []},
        "registrar": {"name": "域名注册商", "sequence": 2, "result": []},
        "name_servers": {"name": "NS 域名服务器", "sequence": 3, "result": []},
        "dnssec": {"name": "域名系统安全扩展", "sequence": 4, "result": []},
        "creation_date": {"name": "创建日期", "sequence": 5, "result": []},
        "expiration_date": {"name": "过期日期", "sequence": 6, "result": []},
    }

    try:
        registered_domain = tldextract.extract(url.netloc).registered_domain
        if not registered_domain:
            return error_result
        domain = whois.whois(registered_domain)
        result_map["name"]["result"] = [
            {"name": domain.name if domain.name else NOT_FOUND}
        ]
        result_map["emails"]["result"] = [
            {"name": domain.emails if domain.emails else NOT_FOUND}
        ]
        result_map["registrar"]["result"] = [
            {"name": domain.registrar if domain.registrar else NOT_FOUND}
        ]
        result_map["name_servers"]["result"] = [
            {"name": domain.name_servers if domain.name_servers else NOT_FOUND}
        ]
        result_map["dnssec"]["result"] = [
            {"name": domain.dnssec if domain.dnssec else NOT_FOUND}
        ]
        if isinstance(domain.creation_date, list):
            result_map["creation_date"]["result"] = [
                {"name": domain.creation_date[0] if domain.creation_date else NOT_FOUND}
            ]
        else:
            result_map["creation_date"]["result"] = [
                {"name": domain.creation_date if domain.creation_date else NOT_FOUND}
            ]
        if isinstance(domain.expiration_date, list):
            result_map["expiration_date"]["result"] = [
                {
                    "name": domain.expiration_date[0]
                    if domain.expiration_date
                    else NOT_FOUND
                }
            ]
        else:
            result_map["expiration_date"]["result"] = [
                {
                    "name": domain.expiration_date
                    if domain.expiration_date
                    else NOT_FOUND
                }
            ]
    except:
        scan_result["result"] = [{"name": "错误", "result": f"{__plugin__}无法连接该网站"}]
        return scan_result

    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
