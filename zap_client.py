"""OWASP ZAP Automation Framework adapter for Module 1."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from exceptions import ScanExecutionError
from models import Target
from normalizer import normalize_zap_alerts
from targeting import parse_target, zap_scope_regex


class ZAPClient:
    """Small, timeout-aware client for ZAP's Automation Framework endpoints."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        api_key: str | None = None,
        request_timeout: int = 15,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.request_timeout = request_timeout
        self.session = session or requests.Session()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        try:
            response = self.session.get(
                f"{self.base_url}{path}", params=query, timeout=self.request_timeout
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise ScanExecutionError(f"ZAP API request failed for {path}: {exc}") from exc

        if not isinstance(payload, dict):
            raise ScanExecutionError(f"ZAP API returned a non-object JSON payload for {path}.")

        if "code" in payload and "planId" not in payload:
            detail = payload.get("detail") or payload.get("message") or payload["code"]
            raise ScanExecutionError(f"ZAP API error for {path}: {detail}")
        return payload

    def scan_counts(self) -> tuple[int, int]:
        spiders = self._get("/JSON/spider/view/scans/").get("scans", [])
        active_scans = self._get("/JSON/ascan/view/scans/").get("scans", [])
        return len(spiders), len(active_scans)

    def run_plan(self, file_path: str | Path) -> str:
        payload = self._get(
            "/JSON/automation/action/runPlan/", {"filePath": str(Path(file_path).resolve())}
        )
        plan_id = payload.get("planId")
        if plan_id is None:
            raise ScanExecutionError(f"ZAP did not return a planId: {payload}")
        return str(plan_id)

    def stop_plan(self, plan_id: str) -> None:
        try:
            self._get("/JSON/automation/action/stopPlan/", {"planId": plan_id})
        except ScanExecutionError as exc:
            print(f"[!] Could not stop ZAP plan {plan_id}: {exc}")

    def poll_plan(
        self,
        plan_id: str,
        initial_counts: tuple[int, int],
        poll_interval: int = 5,
        timeout: int = 360,
    ) -> dict[str, Any]:
        """Wait for plan completion while reporting spider and active scan state."""

        started_at = time.monotonic()
        initial_spiders, initial_active = initial_counts
        while True:
            elapsed = int(time.monotonic() - started_at)
            if elapsed > timeout:
                self.stop_plan(plan_id)
                raise ScanExecutionError(f"ZAP plan {plan_id} exceeded the {timeout}s timeout.")

            progress = self._get("/JSON/automation/view/planProgress/", {"planId": plan_id})
            finished = progress.get("finished")
            spider_percent, active_percent = (100, 100) if finished else (0, 0)
            if not finished:
                try:
                    spiders = self._get("/JSON/spider/view/scans/").get("scans", [])
                    active_scans = self._get("/JSON/ascan/view/scans/").get("scans", [])
                    if len(spiders) > initial_spiders:
                        spider_percent = int(spiders[-1].get("progress", 0))
                    if len(active_scans) > initial_active:
                        active_percent = int(active_scans[-1].get("progress", 0))
                except ScanExecutionError:
                    # Plan progress is authoritative; transient telemetry failures do not abort it.
                    pass

            jobs = progress.get("jobs", [])
            running = [job.get("type", job.get("name", "unknown")) for job in jobs if job.get("status") == "running"]
            current_job = running[0] if running else ("completed" if finished else "processing")
            print(
                f"[ZAP] plan={plan_id} elapsed={elapsed}s job={current_job} "
                f"spider={spider_percent}% active={active_percent}%"
            )
            if finished:
                return progress
            time.sleep(poll_interval)

    def alerts(self, target: Target) -> list[dict[str, Any]]:
        payload = self._get("/JSON/core/view/alerts/", {"baseurl": target.url_without_query})
        alerts = payload.get("alerts", [])
        if not isinstance(alerts, list):
            raise ScanExecutionError("ZAP returned an invalid alerts payload.")
        return alerts

    def execute(
        self,
        target: Target,
        plan_path: str | Path,
        poll_interval: int = 5,
        timeout: int = 360,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        baseline = self.scan_counts()
        plan_id = self.run_plan(plan_path)
        try:
            progress = self.poll_plan(plan_id, baseline, poll_interval, timeout)
        except BaseException:
            self.stop_plan(plan_id)
            raise
        alerts = self.alerts(target)
        return {"plan_id": plan_id, "progress": progress, "alert_count": len(alerts)}, alerts


def write_zap_plan(target: Target, output_file: str | Path, max_duration: int = 5) -> Path:
    """Write a tightly scoped, portable ZAP Automation Framework plan."""

    if max_duration < 1:
        raise ValueError("ZAP active scan duration must be at least one minute.")
    path = Path(output_file).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    target_json = json.dumps(target.url)
    scope_json = json.dumps(zap_scope_regex(target))
    yaml_content = f'''env:
  contexts:
    - name: "Module1-Prototype"
      urls:
        - {target_json}
      includePaths:
        - {scope_json}
jobs:
  - type: spider
  - type: passiveScan-wait
  - type: activeScan
    parameters:
      maxDuration: {max_duration}
'''
    path.write_text(yaml_content, encoding="utf-8")
    return path


# Compatibility wrappers keep the original prototype's public function names usable.
def generate_yaml_plan(target_url: str, output_file: str = "scan_plan.yaml") -> str:
    script_directory = Path(__file__).resolve().parent
    output_path = Path(output_file)
    if not output_path.is_absolute():
        output_path = script_directory / output_path
    path = write_zap_plan(parse_target(target_url), output_path)
    print(f"Scan plan successfully generated and saved to: {path}")
    return str(path)


def trigger_zap_scan(file_path: str, zap_base_url: str = "http://127.0.0.1:8080") -> dict[str, str] | None:
    try:
        plan_id = ZAPClient(zap_base_url).run_plan(file_path)
    except ScanExecutionError as exc:
        print(f"[!] {exc}")
        return None
    response = {"planId": plan_id}
    print(f"ZAP API Response: {response}")
    return response


def poll_plan_progress(
    plan_id: str | int,
    zap_base_url: str = "http://127.0.0.1:8080",
    poll_interval: int = 5,
    timeout: int = 360,
) -> dict[str, Any]:
    client = ZAPClient(zap_base_url)
    return client.poll_plan(str(plan_id), client.scan_counts(), poll_interval, timeout)


def harvest_alerts(target_url: str, zap_base_url: str = "http://127.0.0.1:8080") -> list[dict[str, Any]]:
    target = parse_target(target_url)
    alerts = ZAPClient(zap_base_url).alerts(target)
    print(f"[+] Harvesting alerts for {target.url} ({len(alerts)} found)...")
    for alert in normalize_zap_alerts(alerts):
        print(f"[{alert.severity}] {alert.title} - {alert.endpoint_url}")
    return alerts
