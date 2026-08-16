"""error helpers so UI failures surface in the console, not a crash"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

import httpx
from sqlalchemy.exc import SQLAlchemyError
from textual.css.query import NoMatches

logger = logging.getLogger("kernel_audit.gui")


class AppError(Exception):
    """User-facing error that should be shown in the console"""


#: exceptions the service layer / UI renderers are known to raise. Catch
#: these explicitly instead of a bare ``except Exception`` so genuine bugs
#: are not silently hidden.
APP_ERRORS = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    FileNotFoundError,
    PermissionError,
    ImportError,
    httpx.HTTPError,
    subprocess.TimeoutExpired,
    subprocess.CalledProcessError,
    SQLAlchemyError,
    NoMatches,
)


def log_error(log_terminal: Any, exc: Exception, prefix: str = "Error") -> None:
    """Report an exception through the app console logger, never raising.
    If the console itself fails, redirect to the kernel_audit logger"""
    try:
        log_terminal(f"{prefix}: {exc}", "FAIL")
    except (TypeError, ValueError, AttributeError, NoMatches, OSError, RuntimeError):
        logger.exception("Console failed while reporting %r", exc)


__all__ = ["APP_ERRORS", "AppError", "log_error"]