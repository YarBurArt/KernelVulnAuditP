"""Stdlib-only terminal helpers for the CLI and TUI"""

import os
import sys
import time

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GRAY = "\033[90m"

# used by the audit/report output
CRIT = RED
WARN = YELLOW
OK = GREEN
INFO = CYAN


def supports_color(stream=None) -> bool:
    """Whether ANSI colors are safe to emit for default stdout"""
    stream = stream or sys.stdout
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return os.environ.get("TERM") not in (None, "", "dumb")


def paint(text: str, color: str = "", *, bold: bool = False) -> str:
    """Wrap text in ANSI color unless output is not a color TTY."""
    if not color or not supports_color():
        return text
    code = f"{BOLD}{color}" if bold else color
    return f"{code}{text}{RESET}"


def is_interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def pager(text: str, *, page_size: int = 40) -> None:
    """simple page through long output with a built-in prompt"""
    if not is_interactive():
        print(text)
        return

    lines = text.splitlines()
    total = len(lines)
    start = 0
    while start < total:
        end = min(start + page_size, total)
        print("\n".join(lines[start:end]))
        if end >= total:
            return
        try:
            answer = (
                input(paint("\n-- more -- (Enter/space: next, q: quit) ", DIM))
                .strip()
                .lower()
            )
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if answer in ("q", "quit"):
            print()
            return
        start = end


def _stream_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


class ProgressBar:
    """
    Writes to stderr by default so stdout stays clean for pipes and
    other tools. Disables itself when the stream is not a TTY, in which
    case step/update/finish become no-ops.
    """

    def __init__(
        self,
        total: int = 0,
        *,
        width: int = 30,
        label: str = "",
        color: str = "",
        stream=None,
    ):
        self._total = max(int(total or 0), 0)
        self._width = max(int(width), 4)
        self._label = label
        self._stream = stream or sys.stderr
        self._color = color if supports_color(self._stream) else ""
        self._enabled = _stream_tty(self._stream)
        self._n = 0
        self._start = time.monotonic()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def set_total(self, total: int, label: str | None = None) -> None:
        self._total = max(int(total or 0), 0)
        if label is not None:
            self._label = label

    def set_label(self, label: str) -> None:
        self._label = label

    def update(self, n: int, label: str | None = None) -> None:
        self._n = max(int(n or 0), 0)
        if label is not None:
            self._label = label
        self._draw()

    def step(self, amount: int = 1, label: str | None = None) -> None:
        self.update(self._n + amount, label)

    def detail(self, label: str, note: str = "") -> None:
        """rerender the current state carrying a per-step outcome note"""
        self._label = label
        self._draw(note=note)

    def finish(self, label: str | None = None, note: str = "") -> None:
        if label is not None:
            self._label = label
        if self._total > 0:
            self._n = self._total
        self._draw(final=True, note=note)

    def _draw(self, final: bool = False, note: str = "") -> None:
        if not self._enabled:
            return
        total = self._total if self._total > 0 else max(self._n, 1)
        frac = min(max(self._n / total, 0.0), 1.0)
        pct = int(frac * 100)
        filled = int(frac * self._width)
        bar = "#" * filled + "-" * (self._width - filled)
        if self._color:
            bar = f"{self._color}{bar[:filled]}{RESET}{bar[filled:]}"
        label = f"{self._label} " if self._label else ""
        counter = f"{pct}% {self._n}/{total}" if self._total > 0 else str(self._n)
        line = f"\r{label}[{bar}] {counter} {time.monotonic() - self._start:.1f}s"
        if note:
            line += f" {note}"
        self._stream.write(line)
        if final:
            self._stream.write("\n")
        self._stream.flush()