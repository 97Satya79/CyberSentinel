"""Target parsing, scope construction, and authorization guardrails."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from exceptions import TargetAuthorizationError, TargetValidationError
from models import Target


def parse_target(value: str) -> Target:
    """Parse one absolute HTTP(S) URL into the project's target contract."""

    raw = value.strip()
    if not raw or any(character in raw for character in "\r\n\x00"):
        raise TargetValidationError("Target must be a non-empty, single-line URL.")

    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("Target URL must use http or https.")
    if not parsed.hostname:
        raise TargetValidationError("Target URL must include a host.")
    if parsed.username or parsed.password:
        raise TargetValidationError("Credentials must not be embedded in the target URL.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(f"Invalid target port: {exc}") from exc

    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    host = parsed.hostname.lower().rstrip(".")
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    return Target(
        original_url=raw,
        scheme=scheme,
        host=host,
        port=port or default_port,
        path=path,
        query=parsed.query,
        port_was_specified=port is not None,
    )


def is_local_target(target: Target) -> bool:
    """Return true for loopback/local targets that are safe development defaults."""

    host = target.host.lower()
    if host in {"localhost", "host.docker.internal"} or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback


def require_authorized_target(target: Target, authorized: bool = False) -> None:
    """Require an explicit operator attestation before scanning a remote host."""

    if not is_local_target(target) and not authorized:
        raise TargetAuthorizationError(
            "Remote scans require an explicit authorization attestation. "
            "Pass --authorized only for systems you own or are permitted to test."
        )


def zap_scope_regex(target: Target) -> str:
    """Create a strict ZAP includePaths regex without trailing-slash drift."""

    scope_base = target.url_without_query.rstrip("/")
    return rf"^{re.escape(scope_base)}(?:[/?].*)?$"


def display_target(target: Target) -> str:
    """Return a canonical URL useful in terminal output and audit records."""

    return urlunsplit((target.scheme, target.authority, target.path, target.query, ""))
