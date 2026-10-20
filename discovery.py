"""Nmap-based service discovery and scanner routing decisions."""

from __future__ import annotations

import json
from typing import Any, Callable

from exceptions import ScanExecutionError, ToolUnavailableError
from models import DiscoveredService, ServiceRoutes, Target


DEFAULT_WEB_PORTS = (80, 443, 3000, 5000, 5050, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443)


def discovery_port_spec(target: Target) -> str:
    """Use the requested port when explicit, otherwise use the web-service set."""

    if target.port_was_specified:
        return str(target.port)
    return ",".join(str(port) for port in DEFAULT_WEB_PORTS)


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


def discover_services(
    target: Target,
    scanner_factory: Callable[[], Any] | None = None,
) -> tuple[list[DiscoveredService], dict[str, Any]]:
    """Run a narrow Nmap service scan and return open services plus raw output."""

    if scanner_factory is None:
        try:
            import nmap
        except ImportError as exc:
            raise ToolUnavailableError(
                "Nmap discovery requires python-nmap and the nmap executable. "
                "Install the project requirements and ensure `nmap` is on PATH."
            ) from exc
        scanner_factory = nmap.PortScanner

    scanner = scanner_factory()
    ports = discovery_port_spec(target)
    arguments = "-sV -Pn --open"
    try:
        scanner.scan(hosts=target.host, ports=ports, arguments=arguments)
        hosts = scanner.all_hosts()
    except Exception as exc:
        raise ScanExecutionError(f"Nmap discovery failed for {target.host}: {exc}") from exc

    services: list[DiscoveredService] = []
    for host in hosts:
        host_data = scanner[host]
        protocols = host_data.all_protocols() if hasattr(host_data, "all_protocols") else []
        for protocol in protocols:
            for port, details in host_data.get(protocol, {}).items():
                if details.get("state") != "open":
                    continue
                services.append(
                    DiscoveredService(
                        host=host,
                        port=int(port),
                        protocol=protocol,
                        state=details.get("state", "unknown"),
                        service_name=details.get("name", "unknown"),
                        product=details.get("product", ""),
                        version=details.get("version", ""),
                        tunnel=details.get("tunnel", ""),
                        extrainfo=details.get("extrainfo", ""),
                    )
                )

    services.sort(key=lambda service: (service.protocol, service.port))
    raw_candidate = _json_safe(getattr(scanner, "_scan_result", {}))
    raw_output = raw_candidate if isinstance(raw_candidate, dict) else {"nmap": raw_candidate}
    raw_output.setdefault("command", {"hosts": target.host, "ports": ports, "arguments": arguments})
    raw_output["services"] = [
        {
            "host": service.host,
            "port": service.port,
            "protocol": service.protocol,
            "state": service.state,
            "service_name": service.service_name,
            "product": service.product,
            "version": service.version,
            "tunnel": service.tunnel,
            "extrainfo": service.extrainfo,
        }
        for service in services
    ]
    return services, raw_output


def route_services(services: list[DiscoveredService]) -> ServiceRoutes:
    """Choose which discovered services are in scope for ZAP and SSLyze."""

    web_services = [service for service in services if service.is_web]
    tls_services = [service for service in web_services if service.supports_tls]
    return ServiceRoutes(web_services=web_services, tls_services=tls_services)
