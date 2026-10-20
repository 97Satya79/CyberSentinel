import tempfile
import unittest
from pathlib import Path

from exceptions import TargetAuthorizationError
from targeting import parse_target, require_authorized_target, zap_scope_regex
from zap_client import write_zap_plan


class TargetingTests(unittest.TestCase):
    def test_target_normalizes_default_port_and_path(self):
        target = parse_target("http://127.0.0.1:5050/vulnerabilities/sqli/")

        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 5050)
        self.assertEqual(target.url, "http://127.0.0.1:5050/vulnerabilities/sqli/")

    def test_scope_regex_does_not_introduce_a_double_slash(self):
        target = parse_target("http://127.0.0.1:5050/vulnerabilities/sqli/")
        scope = zap_scope_regex(target)

        self.assertNotIn("//.*", scope)
        self.assertRegex("http://127.0.0.1:5050/vulnerabilities/sqli/?id=1", scope)
        self.assertNotRegex("http://127.0.0.1:5050/vulnerabilities/sqli-admin/", scope)

    def test_remote_target_requires_operator_attestation(self):
        target = parse_target("https://example.com/")

        with self.assertRaises(TargetAuthorizationError):
            require_authorized_target(target)

        require_authorized_target(target, authorized=True)

    def test_generated_plan_uses_the_strict_scope_regex(self):
        target = parse_target("http://127.0.0.1:5050/vulnerabilities/sqli/")
        with tempfile.TemporaryDirectory() as temporary_directory:
            plan_path = write_zap_plan(target, Path(temporary_directory) / "scan_plan.yaml")
            plan = plan_path.read_text(encoding="utf-8")

        self.assertIn('"^http://127\\\\.0\\\\.0\\\\.1:5050/vulnerabilities/sqli(?:[/?].*)?$"', plan)
        self.assertNotIn("//.*", plan)


if __name__ == "__main__":
    unittest.main()
