import tldextract
import whois


__plugin__ = "WHOIS Scanner"
SEQUENCE = 3


NOT_FOUND = "Unknown"


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
        "creation_date": {"name": "Creation date", "sequence": 4, "result": []},
        "expiration_date": {"name": "Expiration date", "sequence": 5, "result": []},
    }

    try:
        registered_domain = tldextract.extract(url.netloc).registered_domain
        if not registered_domain:
            return error_result
        domain = whois.whois(registered_domain, command=True)
        result_map["name"]["result"] = [{"name": domain.name or NOT_FOUND}]
        result_map["emails"]["result"] = [{"name": domain.emails or NOT_FOUND}]
        result_map["registrar"]["result"] = [{"name": domain.registrar or NOT_FOUND}]
        result_map["dnssec"]["result"] = [{"name": domain.dnssec or NOT_FOUND}]
        if isinstance(domain.creation_date, list):
            result_map["creation_date"]["result"] = [
                {"name": domain.creation_date[0] if domain.creation_date else NOT_FOUND}
            ]
        else:
            result_map["creation_date"]["result"] = [
                {"name": domain.creation_date or NOT_FOUND}
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
