"""label + progress bar on a single compact row, hidden until any scan runs"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Label, ProgressBar


class ProgressBox(Horizontal):
    """Holds the progress bar and current-step label for long-time tasks.
    A single-row box, it can be parked inline in the toolbar or on its own row.
    """

    def compose(self) -> ComposeResult:
        # Textual ProgressBar.percentage is progress/total, with total=None
        # it renders "--%" forever. then we feed a 0..1 fraction, so total must be 1.
        yield Label("", id="progress_label", classes="mono dim")
        yield ProgressBar(id="progress_bar", total=1, show_percentage=True, show_eta=False)

    def update(
        self,
        fraction: float,
        label: str = "",
        visible: bool = True,
        final: bool = False,
    ) -> None:
        self.set_class(not visible, "hidden")
        self.query_one("#progress_label", Label).update(label or "")
        self.query_one("#progress_bar", ProgressBar).progress = max(
            0.0, min(1.0, float(fraction))
        )

    def show(self, label: str = "") -> None:
        self.update(0.0, label, visible=True)

    def hide(self) -> None:
        self.update(0.0, "", visible=False)
