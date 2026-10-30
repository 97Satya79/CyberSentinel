"""CyberSentinel Module 1: authorized DAST and VA orchestration pipeline."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from discovery import discover_services, route_services
from exceptions import CyberSentinelError
from models import RawFinding, ScanSummary, TestRecord
from normalizer import normalize_zap_alerts
from storage import DefectDojoStore
from targeting import display_target, parse_target, require_authorized_target
from tls_audit import run_tls_audit
from zap_client import (
    SCAN_POLICIES,
    ZAPClient,
    generate_yaml_plan,
    harvest_alerts,
    poll_plan_progress,
    trigger_zap_scan,
    write_zap_plan,
)


class _Reporter:
    """Mirror pipeline progress to the terminal and, when wired up, to a caller."""

    def __init__(self, emit: Callable[..., None] | None = None) -> None:
        self._emit = emit

    def print(self, message: str) -> None:
        print(message)
        self.log(message)

    def log(self, message: str) -> None:
        if self._emit is not None:
            self._emit("log", message=message)

    def stage(self, stage: str, status: str, message: str = "") -> None:
        if self._emit is not None:
            self._emit("stage", stage=stage, status=status, message=message)

    def send(self, event_type: str, **data: Any) -> None:
        if self._emit is not None:
            self._emit(event_type, **data)


def finding_to_dict(finding: RawFinding) -> dict[str, Any]:
    """Serialise one normalized finding for JSON artifacts and the dashboard."""

    return {
        "source": finding.source,
        "title": finding.title,
        "severity": finding.severity,
        "scan_type": finding.scan_type,
        "endpoint_url": finding.endpoint_url,
        "parameter": finding.metadata.get("parameter") or "",
        "confidence": finding.metadata.get("confidence") or "",
        "cwe": finding.cwe,
        "description": finding.description,
        "mitigation": finding.mitigation,
        "payload": finding.payload,
        "evidence": finding.evidence,
        "reference": finding.metadata.get("reference") or "",
        "metadata": finding.metadata,
    }


def _plan_path(output_directory: Path, target_url: str, multiple_targets: bool) -> Path:
    """Return an audit-friendly scan plan location without overwriting multi-service plans."""

    if not multiple_targets:
        return output_directory / "scan_plan.yaml"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", target_url)
    return output_directory / f"scan_plan_{safe_name[:100]}.yaml"


def run_scan(
    target_url: str,
    *,
    product_name: str | None = None,
    zap_base_url: str = "http://127.0.0.1:8080",
    database_dsn: str | None = None,
    authorized: bool = False,
    output_directory: str | Path | None = None,
    zap_timeout: int = 360,
    zap_poll_interval: int = 5,
    cookie: str | None = None,
    policy: str | None = None,
    emit: Callable[..., None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> ScanSummary:
    """Run the complete Module 1 workflow for one authorized HTTP(S) target.

    The Nmap discovery stage is mandatory. Scanner-specific failures after
    discovery are captured in the returned summary so independent stages can
    continue and their evidence can still be persisted.

    ``emit`` receives structured progress events for programmatic consumers such
    as the dashboard, while terminal output stays available for the CLI.
    """

    report = _Reporter(emit)
    target = parse_target(target_url)
    require_authorized_target(target, authorized)
    summary = ScanSummary(target=target)
    output_path = Path(output_directory or Path(__file__).resolve().parent).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    report.stage("discovery", "started", f"Discovering services on {display_target(target)}")
    report.print(f"[+] Discovering services on {display_target(target)}")
    services, nmap_raw_output = discover_services(target)
    summary.services.extend(services)
    summary.tests.append(TestRecord("Nmap Port Scan", nmap_raw_output))
    routes = route_services(services)
    report.send(
        "services",
        services=[
            {
                "host": service.host,
                "port": service.port,
                "protocol": service.protocol,
                "state": service.state,
                "service_name": service.service_name,
                "product": service.product,
                "version": service.version,
                "is_web": service.is_web,
                "supports_tls": service.supports_tls,
            }
            for service in services
        ],
    )
    report.stage(
        "discovery",
        "completed",
        f"Nmap found {len(services)} service(s); {len(routes.web_services)} web, {len(routes.tls_services)} TLS",
    )

    if not routes.web_services:
        report.print("[*] Nmap found no in-scope web services; ZAP and SSLyze were skipped.")
    else:
        zap_client = ZAPClient(zap_base_url)
        for service in routes.web_services:
            service_target = target.with_service(service)
            plan_path = _plan_path(output_path, service_target.url, len(routes.web_services) > 1)
            try:
                report.print(f"[+] Running ZAP against {display_target(service_target)}")
                report.stage("zap", "started", f"ZAP active scan against {service_target.url}")
                write_zap_plan(service_target, plan_path, cookie=cookie, policy=policy)
                report.send("plan", target=service_target.url, plan_path=str(plan_path), policy=policy or "default")
                zap_metadata, alerts = zap_client.execute(
                    service_target,
                    plan_path,
                    poll_interval=zap_poll_interval,
                    timeout=zap_timeout,
                    policy=policy,
                    on_progress=lambda telemetry: report.send(
                        "progress", engine="zap", target=service_target.url, **telemetry
                    ),
                    on_urls=lambda urls: report.send("urls", engine="zap", target=service_target.url, urls=urls),
                    should_stop=should_stop,
                )
                zap_metadata["plan_path"] = str(plan_path)
                zap_metadata["alerts"] = alerts
                normalized = normalize_zap_alerts(alerts)
                active_findings = [f for f in normalized if f.scan_type == "active"]
                passive_findings = [f for f in normalized if f.scan_type == "passive"]

                summary.tests.append(
                    TestRecord(
                        "ZAP Active Scan",
                        zap_metadata,
                        tuple(active_findings),
                    )
                )
                if passive_findings:
                    summary.tests.append(
                        TestRecord(
                            "ZAP Passive Scan",
                            {"plan_path": str(plan_path), "alert_count": len(passive_findings)},
                            tuple(passive_findings),
                        )
                    )
                for finding in normalized:
                    report.send("finding", **finding_to_dict(finding))
                report.stage(
                    "zap",
                    "completed",
                    f"ZAP returned {len(alerts)} alert(s) for {service_target.url}",
                )
                report.print(
                    f"[+] ZAP harvested {len(active_findings)} active finding(s) "
                    f"and {len(passive_findings)} passive warning(s) from {service_target.url}"
                )
            except CyberSentinelError as exc:
                message = f"ZAP failed for {service_target.url}: {exc}"
                report.print(f"[!] {message}")
                report.stage("zap", "failed", message)
                report.send("error", message=message, stage="zap")
                summary.errors.append(message)
                summary.tests.append(TestRecord("ZAP Active Scan", {"target": service_target.url, "error": str(exc)}))

    for service in routes.tls_services:
        try:
            report.print(f"[+] Running SSLyze against {service.host}:{service.port}")
            report.stage("tls", "started", f"SSLyze TLS audit against {service.host}:{service.port}")
            tls_output, tls_findings = run_tls_audit(target, service)
            summary.tests.append(TestRecord("SSLyze TLS Audit", tls_output, tuple(tls_findings)))
            for finding in tls_findings:
                report.send("finding", **finding_to_dict(finding))
            report.stage("tls", "completed", f"SSLyze normalized {len(tls_findings)} TLS findings")
            report.print(f"[+] SSLyze normalized {len(tls_findings)} TLS findings")
        except CyberSentinelError as exc:
            message = f"SSLyze failed for {service.host}:{service.port}: {exc}"
            report.print(f"[!] {message}")
            report.stage("tls", "failed", message)
            report.send("error", message=message, stage="tls")
            summary.errors.append(message)
            summary.tests.append(
                TestRecord("SSLyze TLS Audit", {"host": service.host, "port": service.port, "error": str(exc)})
            )

    report.stage("harvest", "started", "Persisting normalized findings")
    findings_file = output_path / "findings.json"
    try:
        findings_payload = {
            "target": target.url,
            "summary": {
                "active_count": len(summary.active_findings),
                "passive_count": len(summary.passive_findings),
                "total_count": len(summary.findings),
            },
            "active_findings": [finding_to_dict(f) for f in summary.active_findings],
            "passive_findings": [finding_to_dict(f) for f in summary.passive_findings],
        }
        with open(findings_file, "w", encoding="utf-8") as fh:
            json.dump(findings_payload, fh, indent=2)
        report.print(
            f"[+] Saved {len(summary.findings)} findings "
            f"({len(summary.active_findings)} active, {len(summary.passive_findings)} passive) "
            f"to {findings_file}"
        )
        report.stage("harvest", "completed", f"{len(summary.findings)} finding(s) written to findings.json")
    except OSError as exc:
        report.print(f"[!] Could not write {findings_file}: {exc}")
        report.stage("harvest", "failed", f"Could not write {findings_file}: {exc}")

    if database_dsn:
        store = DefectDojoStore(database_dsn)
        try:
            store.ensure_schema()
            persisted = store.persist_scan(product_name or target.host, target, summary.tests)
            summary.product_id = persisted["product_id"]
            summary.engagement_id = persisted["engagement_id"]
            summary.persisted_findings = persisted["persisted_findings"]
            summary.duplicate_findings = persisted["duplicate_findings"]
            report.print(
                f"[+] Persisted {summary.persisted_findings} findings "
                f"({summary.duplicate_findings} duplicate) to engagement {summary.engagement_id}."
            )
        finally:
            store.close()
    else:
        report.print("[*] PostgreSQL persistence skipped; provide --db-dsn or CYBERSENTINEL_DATABASE_URL.")

    report.send("summary", target=target.url, status=summary.status, findings=[finding_to_dict(f) for f in summary.findings])
    return summary


def _print_finding_group(title: str, findings: list[RawFinding]) -> None:
    if not findings:
        return
    counts = Counter(f.severity.upper() for f in findings)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    breakdown = [f"{s}: {counts[s]}" for s in severity_order if counts.get(s)]
    breakdown_str = f" - {', '.join(breakdown)}" if breakdown else ""
    print(f"\n{title} ({len(findings)} total{breakdown_str}):")
    print("-" * 65)

    unique: dict[tuple[str, str], list[RawFinding]] = {}
    for f in findings:
        key = (f.severity.upper(), f.title)
        unique.setdefault(key, []).append(f)

    for (sev, f_title), group in unique.items():
        sample = group[0]
        extra = f" [Param: {sample.metadata.get('parameter')}]" if sample.metadata.get("parameter") else ""
        print(f"  [{sev}] {f_title}{extra} ({len(group)} occurrence{'s' if len(group) > 1 else ''})")
        print(f"       Example: {sample.endpoint_url}")
        if sample.payload:
            print(f"       Payload: {sample.payload}")


def _print_summary(summary: ScanSummary) -> None:
    print("\n" + "=" * 25 + " CyberSentinel Scan Summary " + "=" * 25)
    print(f"Target: {summary.target.url}")
    print(f"Status: {summary.status}")
    print(f"Discovered services: {len(summary.services)}")
    print(
        f"Findings total: {len(summary.findings)} "
        f"({len(summary.active_findings)} active, {len(summary.passive_findings)} passive)"
    )

    _print_finding_group("🎯 Targeted Active Scan Findings (Exploits)", summary.active_findings)
    _print_finding_group("🛡️ Passive Security & Hygiene Warnings (ZAP Background)", summary.passive_findings)

    if summary.engagement_id is not None:
        print(f"\nEngagement: {summary.engagement_id}")
        print(f"Persisted findings: {summary.persisted_findings}")
        print(f"Duplicates: {summary.duplicate_findings}")
    for error in summary.errors:
        print(f"Error: {error}")
    print("=" * 78)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CyberSentinel Module 1 VA/DAST pipeline")
    parser.add_argument("target", nargs="?", help="Authorized HTTP(S) target URL")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Attest that you own or have permission to scan a non-local target.",
    )
    parser.add_argument("--product-name", help="DefectDojo product name (defaults to target host)")
    parser.add_argument("--zap-url", default="http://127.0.0.1:8080", help="ZAP daemon base URL")
    parser.add_argument(
        "--db-dsn",
        default=os.environ.get("CYBERSENTINEL_DATABASE_URL"),
        help="PostgreSQL DSN; defaults to CYBERSENTINEL_DATABASE_URL",
    )
    parser.add_argument("--output-dir", default=Path(__file__).resolve().parent, help="Directory for generated ZAP plans")
    parser.add_argument("--zap-timeout", type=int, default=360, help="ZAP timeout in seconds")
    parser.add_argument("--zap-poll-interval", type=int, default=5, help="ZAP telemetry interval in seconds")
    parser.add_argument("--init-db", action="store_true", help="Create or validate the PostgreSQL schema, then exit")
    parser.add_argument(
        "--cookie",
        default=None,
        help=(
            "Pre-authenticated session cookie to inject into every ZAP request "
            '(e.g. "PHPSESSID=abc123"). Logout links are automatically excluded '
            "from the spider when this is set."
        ),
    )
    parser.add_argument(
        "--policy",
        default=None,
        choices=sorted(SCAN_POLICIES),
        help=(
            "Named active-scan policy preset. Only the rules in the preset are "
            "enabled; all others are disabled. "
            f"Available: {', '.join(sorted(SCAN_POLICIES))}."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.init_db:
        if not args.db_dsn:
            parser.error("--init-db requires --db-dsn or CYBERSENTINEL_DATABASE_URL")
        store = DefectDojoStore(args.db_dsn)
        try:
            store.ensure_schema()
        finally:
            store.close()
        print("[+] PostgreSQL schema is ready.")
        return 0
    if not args.target:
        parser.error("target is required unless --init-db is used")
    if args.zap_timeout < 1 or args.zap_poll_interval < 1:
        parser.error("ZAP timeout and poll interval must be positive integers")

    try:
        summary = run_scan(
            args.target,
            product_name=args.product_name,
            zap_base_url=args.zap_url,
            database_dsn=args.db_dsn,
            authorized=args.authorized,
            output_directory=args.output_dir,
            zap_timeout=args.zap_timeout,
            zap_poll_interval=args.zap_poll_interval,
            cookie=args.cookie,
            policy=args.policy,
        )
    except CyberSentinelError as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 2
    _print_summary(summary)
    return 1 if summary.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
