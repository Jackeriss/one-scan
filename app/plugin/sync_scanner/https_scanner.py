import logging
from datetime import datetime

from sslyze.server_connectivity import ServerConnectivityTester
from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    Scanner,
    ServerScanRequest,
    ScanCommand,
)
from sslyze.errors import ConnectionToServerFailed

from app.util.config_util import config
from app.constant.constant import UNKNOWN


__plugin__ = "HTTPS Scanner"
SEQUENCE = 4


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
    scan_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result = {"name": __plugin__, "sequence": SEQUENCE, "result": []}
    error_result["result"] = [
        {"name": "Error", "result": [{"name": f"{__plugin__} can't scan this website"}]}
    ]
    result_map = {
        "https": {"name": "Enabled HTTPS", "sequence": 0, "result": []},
        "effective": {"name": "Effective", "sequence": 1, "result": []},
        "subject": {"name": "Subject", "sequence": 2, "result": []},
        "issuer": {"name": "Issuer", "sequence": 3, "result": []},
        "public": {
            "name": "Public key algorithm",
            "sequence": 4,
            "result": [],
        },
        "signature": {
            "name": "Signature hash algorithm",
            "sequence": 5,
            "result": [],
        },
        "before": {
            "name": "Not valid before (UTC)",
            "sequence": 6,
            "result": [],
        },
        "after": {
            "name": "Not valid after (UTC)",
            "sequence": 7,
            "result": [],
        },
        "tls1_2": {"name": "Accepted TLS1.2 cipher suites", "sequence": 8, "result": []},
        "tls1_3": {"name": "Accepted TLS1.3 cipher suites", "sequence": 9, "result": []},
        "pfs": {
            "name": "Perfect Forward Secrecy (PFS)",
            "sequence": 10,
            "result": [],
        },
        "ats": {
            "name": "App Transport Security (ATS)",
            "sequence": 11,
            "result": [],
        },
        "tls1_3_early_data": {"name": "Support TLS1.3 early data", "sequence": 12, "result": []},
        "match": {
            "name": "Leaf certificate subject matches hostname",
            "sequence": 13,
            "result": [],
        },
        "ocsp": {
            "name": "OCSP Must-Staple",
            "sequence": 14,
            "result": [],
        },
        "fallback": {"name": "The TLS_FALLBACK_SCSV mechanism", "sequence": 15, "result": []},
        "ccs": {"name": "The OpenSSL CCS Injection vulnerability", "sequence": 16, "result": []},
        "heartbleed": {"name": "The Heartbleed vulnerability", "sequence": 17, "result": []},
        "crime": {"name": "The CRIME vulnerability", "sequence": 18, "result": []},
        "robot": {"name": "The ROBOT vulnerability", "sequence": 19, "result": []},
    }

    server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(
        url.netloc, 443
    )
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except ConnectionToServerFailed as e:
        return error_result

    scanner = Scanner()
    server_scan_req = ServerScanRequest(
        server_info,
        {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.TLS_1_3_EARLY_DATA,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.HEARTBLEED,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.ROBOT,
        },
    )
    scanner.queue_scan(server_scan_req)
    for server_scan_result in scanner.get_results():
        certificate_result = server_scan_result.scan_commands_results[
            ScanCommand.CERTIFICATE_INFO
        ]
        tls_1_2_cipher_result = server_scan_result.scan_commands_results[
            ScanCommand.TLS_1_2_CIPHER_SUITES
        ]
        tls_1_3_cipher_result = server_scan_result.scan_commands_results[
            ScanCommand.TLS_1_3_CIPHER_SUITES
        ]
        tls_1_3_early_result = server_scan_result.scan_commands_results[
            ScanCommand.TLS_1_3_EARLY_DATA
        ]
        tls_fallback_result = server_scan_result.scan_commands_results[
            ScanCommand.TLS_FALLBACK_SCSV
        ]
        ccs_result = server_scan_result.scan_commands_results[
            ScanCommand.OPENSSL_CCS_INJECTION
        ]
        heartbleed_result = server_scan_result.scan_commands_results[
            ScanCommand.HEARTBLEED
        ]
        crime_result = server_scan_result.scan_commands_results[
            ScanCommand.TLS_COMPRESSION
        ]
        robot_result = server_scan_result.scan_commands_results[
            ScanCommand.ROBOT
        ]

    for certificate_deployment in certificate_result.certificate_deployments:
        for certificate_info in certificate_deployment.received_certificate_chain:
            result_map["subject"]["result"] = [{"name": certificate_info.subject.rfc4514_string()}]
            result_map["issuer"]["result"] = [{"name": certificate_info.issuer.rfc4514_string()}]
            public_key = certificate_info.public_key()
            public_key_name = type(public_key).__name__[1:][:-9]
            if "key_size" in dir(public_key):
                result_map["public"]["result"] = [{"name": f"{public_key_name}{certificate_info.public_key().key_size}"}]
            else:
                result_map["public"]["result"] = [{"name": public_key_name}]
            result_map["signature"]["result"] = [{"name": certificate_info.signature_hash_algorithm.name.upper()}]
            if datetime.now() > certificate_info.not_valid_before and datetime.now() < certificate_info.not_valid_after:
                result_map["effective"]["result"] = True
            result_map["before"]["result"] = [{"name": datetime.strftime(certificate_info.not_valid_before, "%Y-%m-%d %H:%M:%S")}]
            result_map["after"]["result"] = [{"name": datetime.strftime(certificate_info.not_valid_after, "%Y-%m-%d %H:%M:%S")}]
            break
        result_map["https"]["result"] = True
        result_map["match"]["result"] = certificate_deployment.leaf_certificate_subject_matches_hostname
        result_map["ocsp"]["result"] = certificate_deployment.leaf_certificate_has_must_staple_extension
        break

    tls_1_2_cipher_list = [accepted_cipher_suite.cipher_suite.name for accepted_cipher_suite in tls_1_2_cipher_result.accepted_cipher_suites]
    tls_1_3_cipher_list = [accepted_cipher_suite.cipher_suite.name for accepted_cipher_suite in tls_1_3_cipher_result.accepted_cipher_suites]
    result_map["tls1_2"]["result"] = [{"name": tls_1_2_cipher} for tls_1_2_cipher in tls_1_2_cipher_list] if tls_1_2_cipher_list else False
    result_map["tls1_3"]["result"] = [{"name": tls_1_3_cipher} for tls_1_3_cipher in tls_1_3_cipher_list] if tls_1_3_cipher_list else False
    cipher_list = tls_1_2_cipher_list + tls_1_3_cipher_list
    for cipher in cipher_list:
        if "DHE" in cipher:
            result_map["pfs"]["result"] = True
    if set(cipher_list).intersection(ATS_CIPHER_SET):
        result_map["ats"]["result"] = True
    result_map["tls1_3_early_data"]["result"] = tls_1_3_early_result.supports_early_data
    result_map["fallback"]["result"] = tls_fallback_result.supports_fallback_scsv
    result_map["ccs"]["result"] = not ccs_result.is_vulnerable_to_ccs_injection
    result_map["heartbleed"]["result"] = not heartbleed_result.is_vulnerable_to_heartbleed
    result_map["crime"]["result"] = not crime_result.supports_compression
    result_map["robot"]["result"] = [{"name": robot_result.robot_result.name}]

    scan_result["result"] = sorted(
        [item for item in result_map.values()], key=lambda x: x.get("sequence", 0)
    )

    return scan_result
