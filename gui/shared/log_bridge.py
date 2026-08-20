"""Bridge between the kernel_audit Python logger and the TUI console"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from gui.tui import KernelVulnTUI

# map Python level name -> TUI console level label
LEVEL_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARNING": "WARN",
    "ERROR": "FAIL",
    "CRITICAL": "FAIL",
}

#: WARNING/ERROR records also surface as a Textual toast notification
_TOAST_SEVERITY: dict[str, Literal["warning", "error"]] = {
    "WARNING": "warning",
    "ERROR": "error",
    "CRITICAL": "error",
}

#: seconds during which an identical toast message is suppressed; recon
#: warnings often fire once per subsystem scan and would otherwise stack
_TOAST_DEDUP_SEC = 8.0

#: toast messages stay short; the full text is always in the console log
_TOAST_MAX_LEN = 160


class TUIHandler(logging.Handler):
    """redirect kernel_audit log records into the Engine-stdout console"""

    def __init__(self, tui: KernelVulnTUI) -> None:
        super().__init__()
        self._tui = tui
        self._last_toast: dict[str, float] = {}

    def emit(self, record: logging.LogRecord) -> None:
        level = LEVEL_MAP.get(record.levelname, "INFO")
        message = record.getMessage()
        skip_console = bool(getattr(record, "skip_console", False))
        app_thread = getattr(self._tui, "_thread_id", None)
        if app_thread == threading.get_ident():
            # Already on the UI thread, then update the widget directly.
            self._write(level, message, record.levelname, skip_console)
        else:
            # Worker thread, then marshal the whole emit to the event loop so
            # widget lookups never touch Textual off-thread.
            try:
                self._tui.call_from_thread(
                    self._write, level, message, record.levelname, skip_console
                )
            except RuntimeError:
                # drop the log line on closing
                pass

    def _write(
        self,
        level: str,
        message: str,
        levelname: str,
        skip_console: bool = False,
    ) -> None:
        if not skip_console:
            console = self._tui.get_console()
            if console is not None:
                console.log_line(message, level)
        self._notify(levelname, message)

    def _notify(self, levelname: str, message: str) -> None:
        """Surface WARNING/ERROR records as a transient toast notification."""
        severity = _TOAST_SEVERITY.get(levelname)
        if severity is None or not message:
            return
        now = time.monotonic()
        if now - self._last_toast.get(message, 0.0) < _TOAST_DEDUP_SEC:
            return
        self._last_toast[message] = now
        capped = (
            message
            if len(message) <= _TOAST_MAX_LEN
            else message[: _TOAST_MAX_LEN] + "…"
        )
        try:
            self._tui.notify(capped, severity=severity)
        except RuntimeError:
            # toast rack may already be gone while the app is tearing down
            pass