"""Cerberus Guard Bot: a hardened, multi-agent shield for AI-to-AGI systems."""

__version__ = "0.1.0"

# Logging is configured lazily on first use to avoid import-time side effects
_logging_configured = False


def _ensure_logging_configured() -> None:
    """Ensure logging is configured exactly once."""
    global _logging_configured
    if not _logging_configured:
        from cerberus.logging_config import configure_logging
        
        configure_logging()
        _logging_configured = True


# Auto-configure logging for convenience (but can be disabled by setting env var)
import os

if os.environ.get("CERBERUS_AUTO_CONFIGURE_LOGGING", "true").lower() != "false":
    _ensure_logging_configured()

