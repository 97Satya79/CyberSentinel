import unittest

from events import ScanJob, ScanRegistry
from fastapi import HTTPException
from normalizer import normalize_zap_alerts
from orchestrator import finding_to_dict
from web_dashboard import normalize_cookie

SQLI_ALERT = {
    "alert": "SQL Injection - MySQL",
    "risk": "High",
    "cweid": "89",
    "sourceid": "1",
    "url": "http://127.0.0.1:4280/vulnerabilities/sqli/?id=%27",
    "param": "id",
    "confidence": "Medium",
    "attack": "'",
    "evidence": "You have an error in your SQL syntax",
    "solution": "Use parameterized queries.",
    "desc": "SQL injection may be possible.",
}


class DashboardTests(unittest.TestCase):
    def test_cookie_accepts_copied_header_form(self):
        self.assertEqual(
            normalize_cookie("Cookie: security=low; PHPSESSID=abc\n"),
            "security=low; PHPSESSID=abc",
        )
        self.assertEqual(normalize_cookie("security=low; PHPSESSID=abc"), "security=low; PHPSESSID=abc")
        self.assertIsNone(normalize_cookie("   "))

    def test_cookie_rejects_control_characters(self):
        with self.assertRaises(HTTPException):
            normalize_cookie("PHPSESSID=abc\x00def")

    def test_duplicate_zap_alerts_collapse_once(self):
        findings = normalize_zap_alerts([SQLI_ALERT, dict(SQLI_ALERT)])
        self.assertEqual(len(findings), 1)

    def test_finding_payload_carries_every_dashboard_column(self):
        payload = finding_to_dict(normalize_zap_alerts([SQLI_ALERT])[0])
        self.assertEqual(payload["title"], "SQL Injection - MySQL")
        self.assertEqual(payload["severity"], "High")
        self.assertEqual(payload["parameter"], "id")
        self.assertEqual(payload["confidence"], "Medium")
        self.assertEqual(payload["evidence"], "You have an error in your SQL syntax")
        self.assertEqual(payload["mitigation"], "Use parameterized queries.")
        self.assertEqual(payload["cwe"], 89)

    def test_subscriber_receives_replayed_history(self):
        job = ScanJob({"target_url": "http://127.0.0.1/", "cookie": "PHPSESSID=abc"})
        job.emit("log", message="stage one")
        job.emit("finding", **{"title": "X", "severity": "High"})

        queue = job.subscribe()
        events = [queue.get_nowait() for _ in range(2)]

        self.assertEqual([event["type"] for event in events], ["log", "finding"])
        self.assertEqual([event["seq"] for event in events], [0, 1])
        self.assertEqual(len(job.findings), 1)

    def test_public_request_never_leaks_the_cookie(self):
        public = ScanJob({"target_url": "http://127.0.0.1/", "cookie": "PHPSESSID=abc"}).public_request()
        self.assertNotIn("cookie", public)
        self.assertTrue(public["cookie_provided"])

    def test_registry_evicts_finished_jobs_only(self):
        registry = ScanRegistry(max_history=2)
        running = registry.create({"target_url": "http://a/"})
        running.mark_running()
        finished = registry.create({"target_url": "http://b/"})
        finished.finish("completed")
        newest = registry.create({"target_url": "http://c/"})

        self.assertIsNotNone(registry.get(running.id))
        self.assertIsNone(registry.get(finished.id))
        self.assertEqual(registry.running().id, running.id)
        self.assertEqual(newest.status, "queued")


if __name__ == "__main__":
    unittest.main()
