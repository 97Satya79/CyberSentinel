"""Project-specific exceptions used across the Module 1 pipeline."""


class CyberSentinelError(RuntimeError):
    """Base exception for recoverable CyberSentinel failures."""


class TargetValidationError(CyberSentinelError):
    """Raised when a target URL cannot be safely interpreted."""


class TargetAuthorizationError(CyberSentinelError):
    """Raised when an operator has not attested to a remote target."""


class ToolUnavailableError(CyberSentinelError):
    """Raised when an optional scanner dependency is not installed."""


class ScanExecutionError(CyberSentinelError):
    """Raised when a scanner cannot complete a requested operation."""


class PersistenceError(CyberSentinelError):
    """Raised when findings cannot be persisted to PostgreSQL."""
