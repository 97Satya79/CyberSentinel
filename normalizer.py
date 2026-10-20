"""Convert scanner-specific output into the common RawFinding contract."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from models import DiscoveredService, RawFinding


SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
ZAP_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Info",
    "information": "Info",
    "info": "Info",
}


def normalize_severity(value: str | None) -> str:
    return ZAP_SEVERITY_MAP.get((value or "").strip().lower(), "Info")


def parse_cwe(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def normalize_zap_alerts(alerts: list[dict[str, Any]]) -> list[RawFinding]:
    """Map ZAP's alert payload to persistence-ready findings."""

    findings: list[RawFinding] = []
    for alert in alerts:
        findings.append(
            RawFinding(
                source="OWASP ZAP",
                title=alert.get("alert") or alert.get("name") or "Unnamed ZAP Alert",
                severity=normalize_severity(alert.get("risk")),
                cwe=parse_cwe(alert.get("cweid")),
                description=alert.get("desc") or alert.get("description") or "",
                mitigation=alert.get("solution") or "",
                payload=alert.get("attack") or "",
                endpoint_url=alert.get("url") or "",
                evidence=alert.get("evidence") or "",
                metadata={
                    "plugin_id": alert.get("pluginId"),
                    "parameter": alert.get("param"),
                    "confidence": alert.get("confidence"),
                    "reference": alert.get("reference"),
                    "other_info": alert.get("otherinfo"),
                },
            )
        )
    return findings


def _tls_endpoint(service: DiscoveredService) -> str:
    host = f"[{service.host}]" if ":" in service.host else service.host
    return f"https://{host}:{service.port}/"


def _command_result(scan_result: Mapping[str, Any], command: str) -> Mapping[str, Any]:
    attempt = scan_result.get(command, {})
    if not isinstance(attempt, Mapping):
        return {}
    result = attempt.get("result", {})
    return result if isinstance(result, Mapping) else {}


def _tls_version_supported(result: Mapping[str, Any]) -> bool:
    return bool(
        result.get("is_tls_version_supported")
        or result.get("is_ssl_version_supported")
        or result.get("supports_tls")
    )


def _as_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def _expired_certificate(result: Mapping[str, Any]) -> str | None:
    for deployment in result.get("certificate_deployments", []):
        if not isinstance(deployment, Mapping):
            continue
        for certificate in deployment.get("received_certificate_chain", []):
            if not isinstance(certificate, Mapping):
                continue
            not_after = _as_datetime(certificate.get("not_valid_after"))
            if not_after and not_after <= datetime.now(timezone.utc):
                return not_after.isoformat()
    return None


def _weak_cipher_present(result: Mapping[str, Any]) -> str | None:
    weak_markers = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5")
    for cipher in result.get("accepted_cipher_suites", []):
        rendered = json.dumps(cipher, sort_keys=True).upper()
        for marker in weak_markers:
            if marker in rendered:
                return marker
    return None


def normalize_sslyze_report(
    report: Mapping[str, Any], service: DiscoveredService
) -> list[RawFinding]:
    """Extract high-signal TLS weaknesses from SSLyze JSON output.

    The raw SSLyze report is always persisted independently. This normalizer only
    emits findings whose result shapes are stable across SSLyze 6.x releases.
    """

    findings: list[RawFinding] = []
    endpoint = _tls_endpoint(service)
    protocol_checks = (
        ("ssl_2_0_cipher_suites", "SSL 2.0 Supported", "High"),
        ("ssl_3_0_cipher_suites", "SSL 3.0 Supported", "High"),
        ("tls_1_0_cipher_suites", "TLS 1.0 Supported", "Medium"),
        ("tls_1_1_cipher_suites", "TLS 1.1 Supported", "Medium"),
    )

    for server in report.get("server_scan_results", []):
        if not isinstance(server, Mapping):
            continue
        scan_result = server.get("scan_result", {})
        if not isinstance(scan_result, Mapping):
            continue

        certificate_result = _command_result(scan_result, "certificate_info")
        expiry = _expired_certificate(certificate_result)
        if expiry:
            findings.append(
                RawFinding(
                    source="SSLyze",
                    title="Expired TLS Certificate",
                    severity="High",
                    endpoint_url=endpoint,
                    description=f"The presented certificate expired at {expiry}.",
                    mitigation="Replace the expired certificate and verify the complete chain.",
                    evidence=expiry,
                    metadata={"command": "certificate_info"},
                )
            )

        for command, title, severity in protocol_checks:
            result = _command_result(scan_result, command)
            if not result or not _tls_version_supported(result):
                continue
            weak_cipher = _weak_cipher_present(result)
            findings.append(
                RawFinding(
                    source="SSLyze",
                    title=title,
                    severity=severity,
                    endpoint_url=endpoint,
                    description=f"The endpoint accepts the deprecated protocol checked by {command}.",
                    mitigation="Disable deprecated TLS/SSL protocol support in the server configuration.",
                    evidence=json.dumps(result, sort_keys=True),
                    metadata={"command": command},
                )
            )
            if weak_cipher:
                findings.append(
                    RawFinding(
                        source="SSLyze",
                        title="Weak TLS Cipher Suite Supported",
                        severity="Medium",
                        endpoint_url=endpoint,
                        description=f"SSLyze reported a cipher suite containing {weak_cipher}.",
                        mitigation="Remove weak cipher suites from the TLS server configuration.",
                        evidence=weak_cipher,
                        metadata={"command": command, "weak_marker": weak_cipher},
                    )
                )
    return findings
