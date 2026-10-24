import unittest

from models import DiscoveredService
from normalizer import normalize_sslyze_report, normalize_zap_alerts


class NormalizerTests(unittest.TestCase):
    def test_zap_alert_is_mapped_to_contract(self):
        findings = normalize_zap_alerts(
            [
                {
                    "alert": "SQL Injection",
                    "risk": "High",
                    "cweid": "89",
                    "url": "http://127.0.0.1:5050/vulnerabilities/sqli/?id=1",
                    "attack": "' OR '1'='1",
                    "desc": "Injection evidence",
                    "solution": "Use parameterized queries",
                }
            ]
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "High")
        self.assertEqual(findings[0].cwe, 89)
        self.assertEqual(findings[0].payload, "' OR '1'='1")
        self.assertEqual(findings[0].scan_type, "active")

    def test_zap_alert_distinguishes_active_and_passive(self):
        findings = normalize_zap_alerts(
            [
                {"name": "SQL Injection", "sourceid": "1", "attack": "'", "risk": "High"},
                {"name": "Missing Header", "sourceid": "3", "attack": "", "risk": "Low"},
            ]
        )
        self.assertEqual(findings[0].scan_type, "active")
        self.assertEqual(findings[1].scan_type, "passive")

    def test_sslyze_deprecated_protocol_produces_finding(self):
        service = DiscoveredService(
            host="127.0.0.1",
            port=8443,
            protocol="tcp",
            state="open",
            service_name="https",
            tunnel="ssl",
        )
        report = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "tls_1_0_cipher_suites": {
                            "status": "COMPLETED",
                            "result": {"is_tls_version_supported": True},
                        }
                    }
                }
            ]
        }

        findings = normalize_sslyze_report(report, service)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "TLS 1.0 Supported")
        self.assertEqual(findings[0].severity, "Medium")


if __name__ == "__main__":
    unittest.main()
