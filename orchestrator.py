"""CyberSentinel Module 1: authorized DAST and VA orchestration pipeline."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from discovery import discover_services, route_services
from exceptions import CyberSentinelError
from models import ScanSummary, TestRecord
from normalizer import normalize_zap_alerts
from storage import DefectDojoStore
from targeting import display_target, parse_target, require_authorized_target
from tls_audit import run_tls_audit
from zap_client import (
    ZAPClient,
    generate_yaml_plan,
    harvest_alerts,
    poll_plan_progress,
    trigger_zap_scan,
    write_zap_plan,
)


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
) -> ScanSummary:
    """Run the complete Module 1 workflow for one authorized HTTP(S) target.

    The Nmap discovery stage is mandatory. Scanner-specific failures after
    discovery are captured in the returned summary so independent stages can
    continue and their evidence can still be persisted.
    """

    target = parse_target(target_url)
    require_authorized_target(target, authorized)
    summary = ScanSummary(target=target)
    output_path = Path(output_directory or Path(__file__).resolve().parent).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[+] Discovering services on {display_target(target)}")
    services, nmap_raw_output = discover_services(target)
    summary.services.extend(services)
    summary.tests.append(TestRecord("Nmap Port Scan", nmap_raw_output))
    routes = route_services(services)

    if not routes.web_services:
        print("[*] Nmap found no in-scope web services; ZAP and SSLyze were skipped.")
    else:
        zap_client = ZAPClient(zap_base_url)
        for service in routes.web_services:
            service_target = target.with_service(service)
            plan_path = _plan_path(output_path, service_target.url, len(routes.web_services) > 1)
            try:
                print(f"[+] Running ZAP against {display_target(service_target)}")
                write_zap_plan(service_target, plan_path)
                zap_metadata, alerts = zap_client.execute(
                    service_target,
                    plan_path,
                    poll_interval=zap_poll_interval,
                    timeout=zap_timeout,
                )
                zap_metadata["plan_path"] = str(plan_path)
                zap_metadata["alerts"] = alerts
                summary.tests.append(
                    TestRecord(
                        "ZAP Active Scan",
                        zap_metadata,
                        tuple(normalize_zap_alerts(alerts)),
                    )
                )
                print(f"[+] ZAP harvested {len(alerts)} alerts from {service_target.url}")
            except CyberSentinelError as exc:
                message = f"ZAP failed for {service_target.url}: {exc}"
                print(f"[!] {message}")
                summary.errors.append(message)
                summary.tests.append(TestRecord("ZAP Active Scan", {"target": service_target.url, "error": str(exc)}))

    for service in routes.tls_services:
        try:
            print(f"[+] Running SSLyze against {service.host}:{service.port}")
            tls_output, tls_findings = run_tls_audit(target, service)
            summary.tests.append(TestRecord("SSLyze TLS Audit", tls_output, tuple(tls_findings)))
            print(f"[+] SSLyze normalized {len(tls_findings)} TLS findings")
        except CyberSentinelError as exc:
            message = f"SSLyze failed for {service.host}:{service.port}: {exc}"
            print(f"[!] {message}")
            summary.errors.append(message)
            summary.tests.append(
                TestRecord("SSLyze TLS Audit", {"host": service.host, "port": service.port, "error": str(exc)})
            )

    if database_dsn:
        store = DefectDojoStore(database_dsn)
        try:
            store.ensure_schema()
            persisted = store.persist_scan(product_name or target.host, target, summary.tests)
            summary.product_id = persisted["product_id"]
            summary.engagement_id = persisted["engagement_id"]
            summary.persisted_findings = persisted["persisted_findings"]
            summary.duplicate_findings = persisted["duplicate_findings"]
            print(
                f"[+] Persisted {summary.persisted_findings} findings "
                f"({summary.duplicate_findings} duplicate) to engagement {summary.engagement_id}."
            )
        finally:
            store.close()
    else:
        print("[*] PostgreSQL persistence skipped; provide --db-dsn or CYBERSENTINEL_DATABASE_URL.")

    return summary


def _print_summary(summary: ScanSummary) -> None:
    print("\n=== CyberSentinel Module 1 Summary ===")
    print(f"Target: {summary.target.url}")
    print(f"Status: {summary.status}")
    print(f"Discovered services: {len(summary.services)}")
    print(f"Normalized findings: {len(summary.findings)}")
    if summary.engagement_id is not None:
        print(f"Engagement: {summary.engagement_id}")
        print(f"Persisted findings: {summary.persisted_findings}")
        print(f"Duplicates: {summary.duplicate_findings}")
    for error in summary.errors:
        print(f"Error: {error}")


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
        )
    except CyberSentinelError as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 2
    _print_summary(summary)
    return 1 if summary.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
