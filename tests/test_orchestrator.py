import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import orchestrator
from models import DiscoveredService


class OrchestratorTests(unittest.TestCase):
    def test_local_pipeline_routes_zap_and_tls_without_a_live_scanner(self):
        service = DiscoveredService(
            host="127.0.0.1",
            port=5050,
            protocol="tcp",
            state="open",
            service_name="http",
        )
        with tempfile.TemporaryDirectory() as output_directory:
            with patch.object(orchestrator, "discover_services", return_value=([service], {"nmap": "raw"})):
                with patch.object(
                    orchestrator.ZAPClient,
                    "execute",
                    return_value=(
                        {"plan_id": "7", "progress": {"finished": "now"}, "alert_count": 1},
                        [
                            {
                                "alert": "SQL Injection",
                                "risk": "High",
                                "cweid": "89",
                                "url": "http://127.0.0.1:5050/vulnerabilities/sqli/?id=1",
                            }
                        ],
                    ),
                ):
                    summary = orchestrator.run_scan(
                        "http://127.0.0.1:5050/vulnerabilities/sqli/",
                        output_directory=output_directory,
                    )

            self.assertEqual(len(summary.services), 1)
            self.assertEqual(len(summary.findings), 1)
            self.assertEqual(summary.findings[0].title, "SQL Injection")
            self.assertTrue(Path(output_directory, "scan_plan.yaml").exists())
            self.assertFalse(summary.errors)


if __name__ == "__main__":
    unittest.main()
