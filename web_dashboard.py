"""CyberSentinel findings dashboard: FastAPI app serving live scan progress.

Run with:
    python -m uvicorn web_dashboard:app --host 127.0.0.1 --port 5000
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from events import ScanJob, ScanRegistry
from exceptions import CyberSentinelError
from orchestrator import run_scan
from targeting import parse_target, require_authorized_target
from zap_client import SCAN_POLICIES, ZAPClient

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "scan_results"
POLICY_CHOICES = {"all", *SCAN_POLICIES.keys()}
DEFAULT_ZAP_URL = os.environ.get("CYBERSENTINEL_ZAP_URL", "http://127.0.0.1:8080")

app = FastAPI(title="CyberSentinel Dashboard", version="1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
registry = ScanRegistry()


class ScanRequest(BaseModel):
    """One dashboard-initiated scan."""

    target_url: str = Field(..., min_length=8, max_length=2048)
    cookie: str | None = Field(default=None, max_length=4096)
    policy: str = Field(default="all", max_length=40)
    zap_url: str = Field(default_factory=lambda: DEFAULT_ZAP_URL, max_length=512)
    zap_timeout: int = Field(default=360, ge=30, le=3600)
    authorized: bool = False


def normalize_cookie(value: str | None) -> str | None:
    """Accept either ``security=low; PHPSESSID=abc`` or the copied ``Cookie:`` header."""

    if not value:
        return None
    cleaned = " ".join(value.strip().splitlines()).strip()
    if cleaned.lower().startswith("cookie:"):
        cleaned = cleaned[len("cookie:") :].strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise HTTPException(status_code=422, detail="Cookie must not contain control characters.")
    return cleaned or None


def _worker(job: ScanJob) -> None:
    """Execute the pipeline for one job, publishing every stage event."""

    job.mark_running()
    output_directory = RESULTS_DIR / job.id
    policy = job.request["policy"]

    def emit(event_type: str, **data: Any) -> None:
        try:
            job.emit(event_type, **data)
        except Exception:  # a dashboard hiccup must never abort a scan
            pass

    try:
        summary = run_scan(
            job.request["target_url"],
            zap_base_url=job.request["zap_url"],
            authorized=job.request["authorized"],
            output_directory=output_directory,
            zap_timeout=job.request["zap_timeout"],
            cookie=job.request.get("cookie"),
            policy=None if policy == "all" else policy,
            emit=emit,
            should_stop=lambda: job.cancel_requested,
        )
    except CyberSentinelError as exc:
        emit("error", message=str(exc))
        job.finish("failed", error=str(exc))
        return
    except Exception as exc:  # pragma: no cover - defensive for unexpected pipeline faults
        message = f"Unexpected dashboard failure: {exc}"
        emit("error", message=message)
        job.finish("failed", error=message)
        return

    if job.cancel_requested:
        job.finish("cancelled", error="Cancelled by operator", result=_result(summary))
    elif summary.errors:
        job.finish("completed_with_errors", result=_result(summary))
    else:
        job.finish("completed", result=_result(summary))


def _result(summary: Any) -> dict[str, Any]:
    return {
        "target": summary.target.url,
        "status": summary.status,
        "services": len(summary.services),
        "active_count": len(summary.active_findings),
        "passive_count": len(summary.passive_findings),
        "total_count": len(summary.findings),
        "errors": list(summary.errors),
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "dashboard.html", {"default_zap_url": DEFAULT_ZAP_URL})


@app.get("/api/health")
def health(zap_url: str = DEFAULT_ZAP_URL) -> JSONResponse:
    """Preflight so a missing ZAP daemon surfaces before a scan is queued."""

    zap_version = ZAPClient(zap_url, request_timeout=3).version()
    running = registry.running()
    return JSONResponse(
        {
            "zap": {"base_url": zap_url, "reachable": bool(zap_version), "version": zap_version},
            "nmap": {"available": bool(shutil.which("nmap"))},
            "active_scan": running.id if running else None,
            "default_zap_url": DEFAULT_ZAP_URL,
            "policies": sorted(POLICY_CHOICES),
        }
    )


@app.post("/api/scans", status_code=201)
async def start_scan(payload: ScanRequest) -> JSONResponse:
    cookie = normalize_cookie(payload.cookie)
    if payload.policy not in POLICY_CHOICES:
        raise HTTPException(status_code=422, detail=f"Unknown policy {payload.policy!r}.")
    try:
        target = parse_target(payload.target_url)
        require_authorized_target(target, payload.authorized)
    except CyberSentinelError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    running = registry.running()
    if running is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Scan {running.id} is already running against {running.request['target_url']}.",
        )

    job = registry.create(
        {
            "target_url": target.url,
            "cookie": cookie,
            "policy": payload.policy,
            "zap_url": payload.zap_url,
            "zap_timeout": payload.zap_timeout,
            "authorized": payload.authorized,
        }
    )
    job.bind_loop(asyncio.get_running_loop())
    job.emit("scan.queued", **job.public_request())
    thread = threading.Thread(target=_worker, args=(job,), name=f"cybersentinel-{job.id}", daemon=True)
    thread.start()
    return JSONResponse({"scan_id": job.id, "status": job.status}, status_code=201)


@app.get("/api/scans")
def list_scans() -> JSONResponse:
    return JSONResponse([job.to_dict() for job in registry.list_jobs()])


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> JSONResponse:
    job = registry.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    return JSONResponse(job.to_dict(include_events=True))


@app.post("/api/scans/{scan_id}/stop")
def stop_scan(scan_id: str) -> JSONResponse:
    job = registry.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")
    if job.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail=f"Scan {scan_id} already {job.status}.")
    job.request_cancel()
    job.emit("scan.cancelling", message="Cancellation requested; stopping the ZAP plan.")
    return JSONResponse({"scan_id": scan_id, "status": "cancelling"})


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    """Server-Sent Event stream: replayed history followed by live progress."""

    job = registry.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")

    async def stream() -> AsyncIterator[str]:
        queue = job.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield _sse(event)
                if event["type"] == "scan.finished":
                    return
        finally:
            job.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


def _sse(event: dict[str, Any]) -> str:
    return f"id: {event['seq']}\nevent: {event['type']}\ndata: {json.dumps(event)}\n\n"
