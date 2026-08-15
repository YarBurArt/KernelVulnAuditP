"""Bridge between the kernel_audit Python logger and the TUI console"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

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


class TUIHandler(logging.Handler):
    """redirect kernel_audit log records into the Engine-stdout console"""

    def __init__(self, tui: KernelVulnTUI) -> None:
        super().__init__()
        self._tui = tui

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(record, "skip_console", False):
            return
        level = LEVEL_MAP.get(record.levelname, "INFO")
        message = record.getMessage()
        app_thread = getattr(self._tui, "_thread_id", None)
        if app_thread == threading.get_ident():
            # Already on the UI thread, then update the widget directly.
            self._write(level, message)
        else:
            # Worker thread, then marshal the whole emit to the event loop so
            # widget lookups never touch Textual off-thread.
            try:
                self._tui.call_from_thread(self._write, level, message)
            except RuntimeError:
                # drop the log line on closing
                pass

    def _write(self, level: str, message: str) -> None:
        console = self._tui.get_console()
        if console is not None:
            console.log_line(message, level)
