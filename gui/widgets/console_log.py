"""Engine stdout terminal, FAIL / OK / INFO lines, colored and autoscrolling"""

from __future__ import annotations

from textual.widgets import RichLog

from gui.shared.formatting import markup_escape
from presentation.glyphs import unicode_glyph

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
    """RichLog-based terminal used by the Engine stdout tab.

    highlight=True keeps the log legible; a per-line length cap keeps
    Textual safe even when DEBUG logs carry multi-kilobyte dict dumps (the
    full text is still written to logs/kernel_audit.log by the file handler).
    """

    #: longest line rendered in the TUI; longer DEBUG dumps are wrapped so the
    #: per-line Pygments/parse pass never chokes on one huge line
    _MAX_LINE = 4096

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("markup", True)
        kwargs.setdefault("highlight", True)
        kwargs.setdefault("wrap", True)
        kwargs.setdefault("auto_scroll", True)
        kwargs.setdefault("max_lines", 2000)
        super().__init__(*args, **kwargs)

    @staticmethod
    def _cap(line: str) -> str:
        if len(line) > ConsoleLog._MAX_LINE:
            return line[: ConsoleLog._MAX_LINE] + unicode_glyph("…", "...")
        return line

    def log_line(self, message: str, level: str = "INFO") -> None:
        style = _LEVEL_STYLE.get(level, "#8b949e")
        for part in str(message).splitlines() or [""]:
            self.write(
                f"[{style}]{markup_escape(f'[{level}]')} "
                f"{markup_escape(self._cap(part))}"
            )

    def write_raw(self, message: str) -> None:
        for part in str(message).splitlines() or [""]:
            self.write(markup_escape(self._cap(part)))
