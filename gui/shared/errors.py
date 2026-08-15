"""error helpers so UI failures surface in the console, not a crash"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("kernel_audit.gui")


class AppError(Exception):
    """User-facing error that should be shown in the console"""


def log_error(log_terminal: Any, exc: Exception, prefix: str = "Error") -> None:
    """Report an exception through the app console logger, never raising.
    If the console itself fails, redirect to the kernel_audit logger"""
    try:
        log_terminal(f"{prefix}: {exc}", "FAIL")
    except Exception:
        logger.exception("Console failed while reporting %r", exc)