"""In-memory scan jobs that fan orchestrator events out to dashboard subscribers.

The pipeline stages run in a worker thread while Server-Sent Event responses are
served from the asyncio event loop, so every publish crosses threads through
``loop.call_soon_threadsafe``.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from typing import Any

FINDING_EVENT = "finding"


class ScanJob:
    """One dashboard-initiated scan plus its append-only event stream."""

    def __init__(self, request: dict[str, Any]) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.request = dict(request)
        self.events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.status = "queued"
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.started_at = time.time()
        self.finished_at: float | None = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue] = set()

    # -- delivery ----------------------------------------------------------
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Record the loop that live events must be scheduled onto."""

        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        """Attach a subscriber and replay everything already emitted."""

        queue: asyncio.Queue = asyncio.Queue()
        with self._lock:
            for event in self.events:
                queue.put_nowait(event)
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def emit(self, event_type: str, **data: Any) -> None:
        """Publish one event; safe to call from the scan worker thread."""

        event: dict[str, Any] = {"seq": 0, "ts": time.time(), "type": event_type, "data": data}
        with self._lock:
            event["seq"] = len(self.events)
            self.events.append(event)
            if event_type == FINDING_EVENT:
                self.findings.append(data)
            subscribers = tuple(self._subscribers)
        for queue in subscribers:
            self._deliver(queue, event)

    def _deliver(self, queue: asyncio.Queue, event: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            queue.put_nowait(event)
            return
        try:
            loop.call_soon_threadsafe(queue.put_nowait, event)
        except RuntimeError:
            pass

    # -- lifecycle ---------------------------------------------------------
    def request_cancel(self) -> None:
        self._cancel.set()

    @property
    def cancel_requested(self) -> bool:
        return self._cancel.is_set()

    def mark_running(self) -> None:
        self.status = "running"
        self.emit("scan.started", **self.public_request())

    def finish(self, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        self.status = status
        self.result = result
        self.error = error
        self.finished_at = time.time()
        self.emit("scan.finished", status=status, result=result, error=error)

    # -- serialisation -----------------------------------------------------
    def public_request(self) -> dict[str, Any]:
        """Expose the request without leaking the session cookie value."""

        public = {key: value for key, value in self.request.items() if key != "cookie"}
        public["cookie_provided"] = bool(self.request.get("cookie"))
        return public

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            severity = str(finding.get("severity", "Info"))
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def to_dict(self, include_events: bool = False) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "status": self.status,
            "request": self.public_request(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "result": self.result,
            "finding_count": len(self.findings),
            "severity_counts": self.severity_counts(),
        }
        if include_events:
            payload["findings"] = list(self.findings)
            payload["events"] = list(self.events)
        return payload


class ScanRegistry:
    """Bounded store of the dashboard's scan jobs."""

    def __init__(self, max_history: int = 25) -> None:
        self.max_history = max_history
        self._lock = threading.Lock()
        self._jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []

    def create(self, request: dict[str, Any]) -> ScanJob:
        job = ScanJob(request)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.max_history:
                victim = self._find_evictable()
                if victim is None:
                    break
                self._order.remove(victim)
                self._jobs.pop(victim, None)
        return job

    def _find_evictable(self) -> str | None:
        """Only drop finished jobs so an operator never loses an in-flight scan."""

        for job_id in self._order:
            job = self._jobs.get(job_id)
            if job is not None and job.status not in {"queued", "running"}:
                return job_id
        return None

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        with self._lock:
            return [self._jobs[job_id] for job_id in reversed(self._order)]

    def running(self) -> ScanJob | None:
        """Prefer an in-flight scan over one still waiting for its thread."""

        jobs = self.list_jobs()
        for status in ("running", "queued"):
            for job in jobs:
                if job.status == status:
                    return job
        return None
