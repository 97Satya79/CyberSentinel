"""Typed contracts shared by discovery, scanners, normalization, and storage."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlunsplit


@dataclass(frozen=True, slots=True)
class Target:
    """A validated target URL and the network address derived from it."""

    original_url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    port_was_specified: bool

    @property
    def is_tls(self) -> bool:
        return self.scheme == "https"

    @property
    def host_for_url(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def authority(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        if self.port_was_specified or self.port != default_port:
            return f"{self.host_for_url}:{self.port}"
        return self.host_for_url

    @property
    def url(self) -> str:
        return urlunsplit((self.scheme, self.authority, self.path, self.query, ""))

    @property
    def url_without_query(self) -> str:
        return urlunsplit((self.scheme, self.authority, self.path, "", ""))

    def with_service(self, service: "DiscoveredService") -> "Target":
        """Create a scan target for a discovered web service on this host."""

        scheme = "https" if service.supports_tls else "http"
        preserve_path = service.port == self.port
        return Target(
            original_url=self.original_url,
            scheme=scheme,
            host=self.host,
            port=service.port,
            path=self.path if preserve_path else "/",
            query=self.query if preserve_path else "",
            port_was_specified=service.port not in {80, 443},
        )


@dataclass(frozen=True, slots=True)
class DiscoveredService:
    """One open TCP/UDP service returned by Nmap."""

    host: str
    port: int
    protocol: str
    state: str
    service_name: str
    product: str = ""
    version: str = ""
    tunnel: str = ""
    extrainfo: str = ""

    @property
    def is_web(self) -> bool:
        name = self.service_name.lower()
        return "http" in name or self.port in {80, 443, 3000, 5000, 5050, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443}

    @property
    def supports_tls(self) -> bool:
        name = self.service_name.lower()
        return (
            self.tunnel.lower() in {"ssl", "tls"}
            or "https" in name
            or "ssl" in name
            or "tls" in name
            or self.port in {443, 8443, 9443}
        )


@dataclass(frozen=True, slots=True)
class RawFinding:
    """A scanner-neutral finding ready for DefectDojo-style persistence."""

    source: str
    title: str
    severity: str
    endpoint_url: str
    cwe: int | None = None
    description: str = ""
    mitigation: str = ""
    payload: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TestRecord:
    """The raw output and normalized findings from one scanner execution."""

    test_type: str
    raw_output: dict[str, Any]
    findings: tuple[RawFinding, ...] = ()


@dataclass(slots=True)
class ServiceRoutes:
    """Nmap services eligible for the Module 1 scanner adapters."""

    web_services: list[DiscoveredService] = field(default_factory=list)
    tls_services: list[DiscoveredService] = field(default_factory=list)


@dataclass(slots=True)
class ScanSummary:
    """The complete outcome of one Module 1 execution."""

    target: Target
    services: list[DiscoveredService] = field(default_factory=list)
    tests: list[TestRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    product_id: int | None = None
    engagement_id: int | None = None
    persisted_findings: int = 0
    duplicate_findings: int = 0

    @property
    def findings(self) -> list[RawFinding]:
        return [finding for test in self.tests for finding in test.findings]

    @property
    def status(self) -> str:
        return "Completed with errors" if self.errors else "Completed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
