"""SSLyze CLI adapter with JSON collection for Module 1."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from exceptions import ScanExecutionError
from models import DiscoveredService, RawFinding, Target
from normalizer import normalize_sslyze_report


def run_tls_audit(
    target: Target,
    service: DiscoveredService,
    timeout: int = 300,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> tuple[dict[str, Any], list[RawFinding]]:
    """Run SSLyze through its supported JSON CLI output contract."""

    service_target = target.with_service(service)
    endpoint = f"{service_target.host_for_url}:{service.port}"
    report_descriptor, report_name = tempfile.mkstemp(
        prefix="cybersentinel-sslyze-", suffix=".json"
    )
    os.close(report_descriptor)
    report_path = Path(report_name)
    command = [sys.executable, "-m", "sslyze", endpoint, f"--json_out={report_path}"]
    try:
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanExecutionError(f"SSLyze execution failed for {endpoint}: {exc}") from exc

    try:
        if not report_path.exists() or report_path.stat().st_size == 0:
            stderr = getattr(completed, "stderr", "")
            raise ScanExecutionError(
                "SSLyze did not produce a JSON report. Install `sslyze` in the active "
                f"Python environment. stderr: {stderr.strip()}"
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanExecutionError(f"Could not parse SSLyze JSON report for {endpoint}: {exc}") from exc
    finally:
        report_path.unlink(missing_ok=True)

    raw_output = {
        "command": command,
        "return_code": getattr(completed, "returncode", None),
        "stdout": getattr(completed, "stdout", ""),
        "stderr": getattr(completed, "stderr", ""),
        "report": report,
    }
    return raw_output, normalize_sslyze_report(report, service)
