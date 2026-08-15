"""colored list body used inside sandbox run details"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from gui.shared.colors import COLOR
from gui.shared.highlighting import colorize_line


class ColorizedList(Static):
    """Static renderable that applies per-field colors to each line."""

    def __init__(self, lines: list[str], kind: str, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._lines = list(lines or [])
        self._kind = kind

    def update_lines(self, lines: list[str], kind: str) -> None:
        self._lines = list(lines or [])
        self._kind = kind
        self.refresh()

    def render(self) -> Text:
        text = Text()
        for line in self._lines:
            ranges = colorize_line(self._kind, line)
            if ranges:
                pos = 0
                for start, stop, color_name in ranges:
                    if start > pos:
                        text.append(line[pos:start])
                    text.append(line[start:stop], style=COLOR.get(color_name, ""))
                    pos = stop
                if pos < len(line):
                    text.append(line[pos:])
            else:
                text.append(line)
            text.append("\n")
        return text