"""CRIT / WARN / CVE / RUNS status counters"""

from __future__ import annotations

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget

from gui.shared.colors import CRIT, CVE, RUNS, WARN


class MetricsBar(Widget):
    """Metrics row shown in the scan toolbar."""

    crit = reactive(0)
    warn = reactive(0)
    cve = reactive(0)
    runs = reactive(0)

    def update_counts(
        self,
        crit: int | None = None,
        warn: int | None = None,
        cve: int | None = None,
        runs: int | None = None,
    ) -> None:
        """Update only the counters that were provided"""
        if crit is not None:
            self.crit = crit
        if warn is not None:
            self.warn = warn
        if cve is not None:
            self.cve = cve
        if runs is not None:
            self.runs = runs

    def render(self) -> Text:
        text = Text()
        text.append("CRIT: ", style=f"bold {CRIT}")
        text.append(str(self.crit))
        text.append("  WARN: ", style=f"bold {WARN}")
        text.append(str(self.warn))
        text.append("  CVE: ", style=f"bold {CVE}")
        text.append(str(self.cve))
        text.append("  RUNS: ", style=f"bold {RUNS}")
        text.append(str(self.runs))
        return text