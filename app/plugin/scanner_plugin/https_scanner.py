from datetime import datetime

from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand

from app.util.config_util import config


CIPHER_SET = [
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
]


def run(url):
    result = {}
    mini_length = 256
    start_time = None
    end_time = None
    server_info = ServerConnectivityInfo(hostname=url.hostname, port=url.port)
    server_info.test_connectivity_to_server(network_timeout=config.http["timeout"])
    synchronous_scanner = SynchronousScanner()
    certificate_result = synchronous_scanner.run_scan_command(
        server_info, CertificateInfoScanCommand()
    )
    cipher_result = synchronous_scanner.run_scan_command(
        server_info, Tlsv12ScanCommand()
    )
    if certificate_result.certificate_matches_hostname is True:
        result["match_domain"] = 1
    for result in certificate_result.as_text():
        result_map = [x.strip() for x in result.split(": ")]
        if len(result_map) == 2:
            result["open_https"] = 1
            if result_map[0] == "Public Key Algorithm":
                if result_map[1] == "_RSAPublicKey":
                    mini_length = 2048
            if result_map[0] == "Key Size":
                if int(result_map[1]) >= mini_length:
                    result["safe_pub"] = 1
            if result_map[0] == "Signature Algorithm":
                if result_map[1] == "sha256":
                    result["safe_signature"] = 1
            if "Apple" in result_map[0]:
                if result_map[1] == "OK - Certificate is trusted":
                    result["trusted_certificate"] = 1
            if result_map[0] == "Not Before":
                start_time = result_map[1]
            if result_map[0] == "Not After":
                end_time = result_map[1]
    if start_time and end_time:
        if (
            datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S") < datetime.now()
            and datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") > datetime.now()
        ):
            result["effective"] = 1
    cipher_list = [cipher.name for cipher in cipher_result.accepted_cipher_list]
    if cipher_list:
        result["support_tls1_2"] = 1
        for cipher in cipher_list:
            if "DHE" in cipher:
                result["pfs"] = 1
        if set(cipher_list).intersection(set(CIPHER_SET)):
            result["ios_cipher"] = 1
            result["follow_ats"] = 1
    return result
