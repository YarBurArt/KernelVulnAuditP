"""Tests for the TUI log bridge: console routing + toast notifications.

WARNING/ERROR log records surface both in the Engine-stdout console and as
transient Textual toasts; identical messages are de-duplicated within a short
window so a burst of the same recon warning does not stack toasts.
"""

import logging

from gui.shared.log_bridge import TUIHandler


class FakeConsole:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str]] = []

    def log_line(self, message: str, level: str = "INFO") -> None:
        self.lines.append((level, message))


class FakeTUI:
    def __init__(self) -> None:
        self.console = FakeConsole()
        self.toasts: list[tuple[str, str]] = []

    def get_console(self):
        return self.console

    def call_from_thread(self, fn, *args, **kwargs):
        fn(*args, **kwargs)

    def notify(self, message: str, severity: str = "information", **kwargs) -> None:
        self.toasts.append((severity, message))


def _record(handler: TUIHandler, levelname: str, message: str, skip_console=False):
    record = logging.LogRecord(
        name="kernel_audit.test",
        level=logging.getLevelName(levelname),
        pathname="",
        lineno=0,
        msg=message,
        args=None,
        exc_info=None,
    )
    record.levelname = levelname
    if skip_console:
        record.__dict__["skip_console"] = True
    handler.emit(record)


def test_info_goes_to_console_without_toast():
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "INFO", "collecting kernel info")
    assert tui.console.lines == [("INFO", "collecting kernel info")]
    assert tui.toasts == []


def test_warning_toasts_with_severity():
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "WARNING", "No linpeas found")
    assert tui.console.lines == [("WARN", "No linpeas found")]
    assert tui.toasts == [("warning", "No linpeas found")]


def test_error_toasts_with_severity():
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "ERROR", "getcap failed")
    assert tui.toasts == [("error", "getcap failed")]
    _record(handler, "CRITICAL", "kernel Oops")
    assert tui.toasts == [("error", "getcap failed"), ("error", "kernel Oops")]


def test_identical_warning_deduped_within_window(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr("gui.shared.log_bridge.time.monotonic", lambda: clock["now"])
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "WARNING", "same warning")
    clock["now"] += 2.0  # inside the 8s window
    _record(handler, "WARNING", "same warning")
    assert len(tui.toasts) == 1
    clock["now"] += 9.0  # outside the window -> allowed again
    _record(handler, "WARNING", "same warning")
    assert len(tui.toasts) == 2


def test_long_toast_message_is_capped(monkeypatch):
    monkeypatch.setattr("gui.shared.log_bridge._TOAST_MAX_LEN", 20)
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "WARNING", "a" * 50)
    assert tui.toasts == [("warning", "a" * 20 + "…")]


def test_skip_console_still_toasts():
    """log_terminal() writes the console itself and flags skip_console, but the
    warning/error still deserves a toast."""
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "ERROR", "async task failed", skip_console=True)
    assert tui.console.lines == []
    assert tui.toasts == [("error", "async task failed")]


def test_empty_message_no_toast():
    tui = FakeTUI()
    handler = TUIHandler(tui)
    _record(handler, "WARNING", "")
    assert tui.toasts == []