"""Left pane of the Engine-stdout tab: the big scan stages checklist."""

from __future__ import annotations

import time

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Static

_STAGE_STYLE = {
    "idle": (" ", "#8b949e"),
    "running": ("●", "#58a6ff"),
    "done": ("✓", "#2ec27e"),
    "fail": ("✗", "#ff5f5f"),
}

_STATUS_LABEL = {
    "idle": "idle",
    "running": "running",
    "done": "done",
    "fail": "failed",
}

#: (key, display name, description) for the top-level scan stages
STAGES = [
    ("local", "Local Recon", "on-host hardening, SELinux, capabilities, CVE hints"),
    ("feeds", "TI Feeds", "KEV / NIST / OSV / GitHub threat-intel"),
    ("full", "Full Cycle", "local recon + threat feeds together"),
    ("exec", "Exec Tests", "sandbox PoC compilation and execution"),
]

#: cap on rendered sub-steps per stage
#: raised so longer runs (per-CVE execution tests) show their real detail
_MAX_SUB_STEPS = 14


#: progress-bar labels that are just the stage headline and would duplicate
#: the stage name as a sub-step -> dropped
_HEADLINE_LABELS = {
    "local recon",
    "threat-intel feeds",
    "threat feeds",
    "executing pocs",
}


def stage_for_label(label: str) -> str | None:
    """Map a progress-bar label back to its owning stage key."""
    low = str(label or "").lower()
    if low in ("local recon", "lynis", "linpeas", "les", "selinux/caps", "hardening"):
        return "local"
    if low in ("threat-intel feeds", "threat feeds", "kev", "nist", "osv", "github"):
        return "feeds"
    if low in ("executing pocs",) or low.startswith("cve-"):
        return "exec"
    return None


class StageRow(Static):
    """One stage: status marker + name on the first line, sub-steps below tree like.
    Each sub-step carries an optional outcome note rendered after its label, and the header shows how
    long the stage ran once it finishes.
    """

    def __init__(
        self, key: str, name: str, description: str = "", *args, **kwargs
    ) -> None:
        self._key = key
        self._stage_name = name
        self._description = description
        self._status = "idle"
        self._current: str = ""
        self._current_note: str = ""
        self._done: list[tuple[str, str]] = []
        self._summary: str = ""
        self._started: float | None = None
        self._duration: float | None = None
        super().__init__(*args, id=f"stage-{key}", **kwargs)
        self._render_row()

    def set_status(self, status: str) -> None:
        if status == "running":
            if self._status != "running":
                self._done = []
                self._current = ""
                self._current_note = ""
                self._summary = ""
                self._duration = None
                self._started = time.monotonic()
        else:
            # never lose the in-flight sub-step when a stage completes
            if status == "done" and self._current:
                self._add_done(self._current, self._current_note)
            self._current = ""
            self._current_note = ""
            if self._started is not None:
                self._duration = time.monotonic() - self._started
        self._status = status
        self._render_row()

    def set_running(self, detail: str, note: str = "") -> None:
        if self._current and self._current != detail:
            self._add_done(self._current, self._current_note)
        self._current = detail
        self._current_note = note
        self._render_row()

    def finish(self, detail: str = "", note: str = "") -> None:
        if detail and detail != self._current:
            self._add_done(detail, note)
        elif self._current:
            self._add_done(self._current, self._current_note or note)
        self._current = ""
        self._current_note = ""
        self._render_row()

    def _add_done(self, label: str, note: str = "") -> None:
        if label and (not self._done or self._done[-1][0] != label):
            self._done.append((label, note))

    def set_summary(self, text: str) -> None:
        if text and text != self._summary:
            self._summary = text
            self._render_row()

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        m, s = divmod(int(seconds), 60)
        return f"{m}m{s:02d}s"

    def _render_row(self) -> None:
        marker, color = _STAGE_STYLE.get(self._status, _STAGE_STYLE["idle"])
        status = _STATUS_LABEL.get(self._status, "")
        suffix = ""
        if self._status == "running":
            suffix = f" [dim]{status}[/]"
        elif self._status == "fail":
            suffix = f" [bold {color}]{status}[/]"
        summary = f"  [dim]· {self._summary}[/]" if self._summary else ""
        duration = ""
        if self._status in ("done", "fail") and self._duration is not None:
            duration = f"  [dim]({self._format_duration(self._duration)})[/]"
        rows = [
            f"[{color}]{marker}[/] [bold]{self._stage_name}[/]{suffix}{duration}{summary}"
        ]
        for label, note in self._done[-_MAX_SUB_STEPS:]:
            note_txt = f"  [dim]· {note}[/]" if note else ""
            rows.append(f"    [dim]✓ {label}[/]{note_txt}")
        if self._current:
            note_txt = f"  [dim]· {self._current_note}[/]" if self._current_note else ""
            rows.append(f"    [{color}]* {self._current}[/]{note_txt}")
        if len(self._done) > _MAX_SUB_STEPS:
            rows.append(
                f"    [dim]+{len(self._done) - _MAX_SUB_STEPS} more[/]"
            )
        if self._status == "idle":
            rows = [f"[dim]{rows[0]}[/]"]
            if self._description:
                rows.append(f"    [dim]{self._description}[/]")
        self.update("\n".join(rows))


class StagesPanel(VerticalScroll):
    """Big-stage checklist for the Engine-stdout tab / left pane
    The pane auto-scales, its width tracks the widest stage row, clamped to
    _MAX_FRACTION of the container
    """

    DEFAULT_CSS = """
    StagesPanel {
        padding: 1;
        background: #010409;
        border: round #30363d;
    }

    StagesPanel StageRow {
        height: auto;
    }
    """

    #: upper bound on the left pane as a fraction of the container width
    _MAX_FRACTION = 0.55
    #: preferred share of the width so the pane keeps room for per-stage detail
    _TARGET_FRACTION = 0.30
    #: lower bound so a few short rows never collapse the pane
    _MIN_WIDTH = 16

    def compose(self) -> ComposeResult:
        yield Static("STAGES", classes="section-label")
        for key, name, description in STAGES:
            yield StageRow(key, name, description)

    def on_mount(self) -> None:
        self.set_timer(0.05, self._autoscale)

    def on_resize(self) -> None:
        self._autoscale()

    def _autoscale(self) -> None:
        """Size the pane to its widest rendered line, within 22-40%."""
        parent_region = getattr(self.parent, "region", None)
        if parent_region is not None and getattr(parent_region, "width", 0) > 0:
            total = parent_region.width
        else:
            total = self.screen.size.width
        total = max(total, 1)
        width = self._MIN_WIDTH
        for row in self.query(StageRow):
            renderable = row.render()
            if renderable is None:
                continue
            plain = str(getattr(renderable, "plain", renderable))
            for line in plain.splitlines():
                width = max(width, len(line))
        width += 4  # padding + border
        lo = int(total * self._TARGET_FRACTION)
        width = max(width, lo)
        width = min(width, int(total * self._MAX_FRACTION))
        self.styles.width = f"{width}"

    def set_stage(self, key: str, status: str) -> None:
        try:
            self.query_one(f"#stage-{key}", StageRow).set_status(status)
        except NoMatches:
            pass
        self._autoscale()

    def set_running(self, key: str, detail: str, note: str = "") -> None:
        try:
            self.query_one(f"#stage-{key}", StageRow).set_running(detail, note)
        except NoMatches:
            pass
        self._autoscale()

    def finish_stage(self, key: str, detail: str = "", note: str = "") -> None:
        try:
            self.query_one(f"#stage-{key}", StageRow).finish(detail, note)
        except NoMatches:
            pass
        self._autoscale()

    def set_stage_summary(self, key: str, summary: str) -> None:
        try:
            self.query_one(f"#stage-{key}", StageRow).set_summary(summary)
        except NoMatches:
            pass
        self._autoscale()


__all__ = ["STAGES", "_HEADLINE_LABELS", "StagesPanel", "stage_for_label"]