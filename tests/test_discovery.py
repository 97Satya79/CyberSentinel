import unittest

from discovery import discover_services, route_services
from targeting import parse_target


class FakeHost(dict):
    def all_protocols(self):
        return ["tcp"]


class FakeScanner(dict):
    def __init__(self):
        super().__init__()
        self["127.0.0.1"] = FakeHost(
            {
                "tcp": {
                    5050: {"state": "open", "name": "http", "product": "Werkzeug"},
                    8443: {"state": "open", "name": "https", "tunnel": "ssl"},
                    22: {"state": "open", "name": "ssh"},
                }
            }
        )
        self._scan_result = {"nmap": {"command_line": "fake nmap"}}
        self.received = None

    def scan(self, **kwargs):
        self.received = kwargs

    def all_hosts(self):
        return ["127.0.0.1"]


class DiscoveryTests(unittest.TestCase):
    def test_discovery_collects_open_services_and_routes_web_tls(self):
        scanner = FakeScanner()
        target = parse_target("http://127.0.0.1:5050/")

        services, raw = discover_services(target, scanner_factory=lambda: scanner)
        routes = route_services(services)

        self.assertEqual(scanner.received["ports"], "5050")
        self.assertEqual([service.port for service in services], [22, 5050, 8443])
        self.assertEqual([service.port for service in routes.web_services], [5050, 8443])
        self.assertEqual([service.port for service in routes.tls_services], [8443])
        self.assertEqual(raw["services"][1]["service_name"], "http")


if __name__ == "__main__":
    unittest.main()
