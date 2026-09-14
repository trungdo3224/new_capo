"""C.A.P.O exception hierarchy.

Provides structured error types so callers can catch specific
failure modes instead of relying on generic ValueError/RuntimeError.
"""


class CapoError(Exception):
    """Base exception for all C.A.P.O errors."""


class TargetError(CapoError):
    """Raised when no target is set or the target format is invalid."""


class ToolNotFoundError(CapoError):
    """Raised when a required external binary is not in PATH."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(f"{tool_name} not found in PATH. Install it first.")


class StateError(CapoError):
    """Raised on state file corruption or schema migration failure."""


class ScanError(CapoError):
    """Raised when a scan execution fails (timeout, bad exit code, etc.)."""


class SessionError(CapoError):
    """Raised on session-related failures (not found, duplicate name, etc.)."""


class GraphError(CapoError):
    """Raised on graph node/edge operation failures (not found, invalid, etc.)."""


class ConfigError(CapoError):
    """Raised on configuration or YAML file errors (invalid filename, not found, etc.)."""
