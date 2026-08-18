"""Shared base screen TUI, common key bindings and navigation actions"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen

from gui.widgets.console_log import ConsoleLog

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
        """The scrollable to drive with j/k/arrows.

        Prefers the focused scrollable widget, then the engine console (the
        big scroll area of the Engine-stdout tab), then the first currently
        visible list. Hidden tab panes keep ``display=True`` on their
        children, so plain ``widget.display`` is not enough -- an ancestor
        must be inspected to skip lists from inactive tabs.
        """
        focused = self.focused
        if focused is not None and focused.is_scrollable and self._rendered(focused):
            return focused
        console = self.query_one_optional(ConsoleLog)
        if console is not None and self._rendered(console):
            return console
        for widget in self.query(VerticalScroll):
            if self._rendered(widget):
                return widget
        return None

    @staticmethod
    def _rendered(widget) -> bool:
        """True when the widget and every ancestor is currently displayed."""
        node = widget
        while node is not None:
            if not node.display:
                return False
            node = node.parent
        return True

    def action_vi_down(self) -> None:
        target = self._scroll_target()
        if target is not None:
            target.scroll_down(animate=False)

    def action_vi_up(self) -> None:
        target = self._scroll_target()
        if target is not None:
            target.scroll_up(animate=False)
