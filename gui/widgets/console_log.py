"""Engine stdout terminal, FAIL / OK / INFO lines, colored and autoscrolling"""

from __future__ import annotations

from textual.widgets import RichLog

from gui.shared.formatting import markup_escape

_LEVEL_STYLE = {
    "FAIL": "#ff5f5f",
    "ERROR": "#ff5f5f",
    "CRITICAL": "#e01b24",
    "WARN": "#ff7800",
    "WARNING": "#ff7800",
    "OK": "#2ec27e",
    "SUCCESS": "#2ec27e",
    "INFO": "#8b949e",
    "DEBUG": "#8b949e",
}


class ConsoleLog(RichLog):
    """RichLog-based terminal used by the Engine stdout tab."""

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("markup", True)
        kwargs.setdefault("highlight", True)
        kwargs.setdefault("wrap", True)
        kwargs.setdefault("auto_scroll", True)
        kwargs.setdefault("max_lines", 2000)
        super().__init__(*args, **kwargs)

    def log_line(self, message: str, level: str = "INFO") -> None:
        style = _LEVEL_STYLE.get(level, "#8b949e")
        self.write(
            f"[{style}]{markup_escape(f'[{level}]')} {markup_escape(message)}"
        )

    def write_raw(self, message: str) -> None:
        self.write(markup_escape(message))
