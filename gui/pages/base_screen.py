"""Shared base screen TUI, common key bindings and navigation actions"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen

if TYPE_CHECKING:
    # for TUI class annotation
    from gui.tui import KernelVulnTUI


class BaseScreen(Screen):
    """Base for the three TUI pages"""

    PAGE: ClassVar[str] = ""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("j", "vi_down", "Scroll down"),
        Binding("down", "vi_down", "Scroll down"),
        Binding("k", "vi_up", "Scroll up"),
        Binding("up", "vi_up", "Scroll up"),
        Binding("q", "quit_app", "Quit"),
    ]

    @property
    def tui(self) -> KernelVulnTUI:
        """Typed accessor for the owning application."""
        return cast("KernelVulnTUI", self.app)

    def action_quit_app(self) -> None:
        self.app.exit()

    def _scroll_target(self):
        """The focused scrollable widget, or the first visible one on pag."""
        focused = self.focused
        if focused is not None and focused.is_scrollable:
            return focused
        for widget in self.query(VerticalScroll):
            if widget.display:
                return widget
        return None

    def action_vi_down(self) -> None:
        target = self._scroll_target()
        if target is not None:
            target.scroll_down(animate=False)

    def action_vi_up(self) -> None:
        target = self._scroll_target()
        if target is not None:
            target.scroll_up(animate=False)
