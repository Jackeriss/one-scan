""" 扫描 SSL 证书相关信息 """
from datetime import datetime

from sslyze.server_connectivity_tester import ServerConnectivityTester
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand

from app.util.config_util import config


__plugin__ = "SSL 扫描器"
SEQUENCE = 3


ATS_CIPHER_SET = (
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
)


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
        "https": {"name": "是否开启 HTTPS", "sequence": 0, "result": False},
        "match": {"name": "证书是否与域名匹配", "sequence": 1, "result": False},
        "signature": {"name": "签名是否安全（使用 SHA256）", "sequence": 2, "result": False},
        "pub": {
            "name": "公钥是否安全（ECDSA_256+ 或 RSA_2048+）",
            "sequence": 3,
            "result": False,
        },
        "effective": {"name": "是否在有效期内", "sequence": 4, "result": False},
        "tls1_2": {"name": "是否支持 TLS1.2", "sequence": 5, "result": False},
        "pfs": {"name": "是否完全前向保密（PFS）", "sequence": 6, "result": False},
        "ats": {"name": "是否遵循苹果 ATS 标准", "sequence": 7, "result": False},
        "ccs": {"name": "没有 CCS 漏洞", "sequence": 8, "result": False},
        "heartbleed": {"name": "没有 Heartbleed 漏洞", "sequence": 9, "result": False},
    }
    mini_length = 256
    start_time = None
    end_time = None

    try:
        server_tester = ServerConnectivityTester(hostname=url.netloc, port=url.port)
        server_info = server_tester.perform()
    except:
        return error_result

    synchronous_scanner = SynchronousScanner()
    certificate_result = synchronous_scanner.run_scan_command(
        server_info, CertificateInfoScanCommand()
    )
    cipher_result = synchronous_scanner.run_scan_command(
        server_info, Tlsv12ScanCommand()
    )
    ccs_result = synchronous_scanner.run_scan_command(
        server_info, OpenSslCcsInjectionScanCommand()
    )
    heartbleed_result = synchronous_scanner.run_scan_command(
        server_info, HeartbleedScanCommand()
    )

    if certificate_result.leaf_certificate_subject_matches_hostname:
        result_map["match"]["result"] = True

    for result in certificate_result.as_text():
        result_list = [x.strip() for x in result.split(": ")]
        if len(result_list) == 2:
            result_map["https"]["result"] = True
            if result_list[0] == "Public Key Algorithm":
                if result_list[1] == "_RSAPublicKey":
                    mini_length = 2048
            if result_list[0] == "Key Size":
                if int(result_list[1]) >= mini_length:
                    result_map["pub"]["result"] = True
            if result_list[0] == "Signature Algorithm":
                if result_list[1] == "sha256":
                    result_map["signature"]["result"] = True
            if result_list[0] == "Not Before":
                start_time = result_list[1]
            if result_list[0] == "Not After":
                end_time = result_list[1]

    if start_time and end_time:
        if (
            datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S") < datetime.now()
            and datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") > datetime.now()
        ):
            result_map["effective"]["result"] = True
    cipher_list = [cipher.name for cipher in cipher_result.accepted_cipher_list]
    if cipher_list:
        result_map["tls1_2"]["result"] = True
        for cipher in cipher_list:
            if "DHE" in cipher:
                result_map["pfs"]["result"] = True
        if set(cipher_list).intersection(ATS_CIPHER_SET):
            result_map["ats"]["result"] = True
    if not ccs_result.is_vulnerable_to_ccs_injection:
        result_map["ccs"]["result"] = True
    if not heartbleed_result.is_vulnerable_to_heartbleed:
        result_map["heartbleed"]["result"] = True

    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result