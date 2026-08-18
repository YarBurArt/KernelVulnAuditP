"""base scan page, compose TUI elements"""

from __future__ import annotations

from typing import ClassVar

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Resize
from textual.widgets import Button, Footer, Static, TabbedContent, TabPane

from gui.pages.base_screen import BaseScreen
from gui.widgets.console_log import ConsoleLog
from gui.widgets.metrics_bar import MetricsBar
from gui.widgets.progress_box import ProgressBox
from gui.widgets.stages_panel import StagesPanel

#: (TabPane id, key) pairs, in visual order. TabbedContent itself has no key
#: bindings, so on a mouse-less pure TTY the tabs are only reachable through
#: these numbered shortcuts plus [ ] cycling.
_TAB_KEYS = [
    ("tab-audit", "1", "Hardening"),
    ("tab-selinux", "2", "SELinux"),
    ("tab-caps", "3", "Capabilities"),
    ("tab-cve", "4", "Exploit Vectors"),
    ("tab-sandbox", "5", "Sandbox Runs"),
    ("tab-engine", "6", "Engine stdout"),
]


class ScanPage(BaseScreen):
    """scan toolbar | result tabs, split engine output with detailed log"""

    PAGE = "scan"
    _PROGRESS_INLINE_WIDTH = 64
    _PROGRESS_MIN_WIDE_TERMINAL = 150
    _PROGRESS_GROUP = "progress-relayout"
    _relocating = False

    BINDINGS: ClassVar[
        list[Binding | tuple[str, str] | tuple[str, str, str]]
    ] = [
        *BaseScreen.BINDINGS,
        *[
            Binding(key, f"goto_tab('{pane_id}')", f"Tab: {label}", show=False)
            for pane_id, key, label in _TAB_KEYS
        ],
        # vim-style navigation: h/l switch tabs, j/k (BaseScreen) scroll
        Binding("h", "previous_tab", "Previous tab"),
        Binding("l", "next_tab", "Next tab"),
        Binding("[", "previous_tab", "Previous tab", show=False),
        Binding("]", "next_tab", "Next tab", show=False),
    ]

    @staticmethod
    def compose() -> ComposeResult:
        with Vertical(classes="page"):
            with Vertical(id="toolbar_area"):
                with Horizontal(classes="toolbar", id="toolbar"):
                    with Horizontal(classes="btn-group"):
                        yield Button("Local Recon", id="local_btn")
                        yield Button("TI Feeds", id="feeds_btn")
                    yield Button("Full Cycle", id="full_btn")
                    yield Button("Exec Tests", id="exec_btn")
                    yield Static("", classes="spacer")
                    yield Button("Report", id="report_btn")
                    yield MetricsBar(id="metrics_bar")
                yield ProgressBox(id="progress_box", classes="hidden")
            with TabbedContent():
                with TabPane("Kernel Hardening", id="tab-audit"):
                    yield VerticalScroll(id="audit_list")
                with TabPane("SELinux Hardening", id="tab-selinux"):
                    yield VerticalScroll(id="selinux_list")
                with TabPane("Capabilities mistakes", id="tab-caps"):
                    yield VerticalScroll(id="caps_list")
                with TabPane("Exploit Vectors", id="tab-cve"):
                    yield VerticalScroll(id="cve_list")
                with TabPane("Sandbox Runs", id="tab-sandbox"):
                    yield VerticalScroll(id="sandbox_list")
                with TabPane("Engine stdout", id="tab-engine"), Horizontal(id="engine_out"):
                    yield StagesPanel(id="stages_panel")
                    yield ConsoleLog(id="console_log")
        yield Footer()

    def _tabbed(self) -> TabbedContent:
        return self.query_one(TabbedContent)

    def action_goto_tab(self, pane_id: str) -> None:
        self._tabbed().active = pane_id

    def _tab_order(self) -> list[str]:
        return [pane.id for pane in self._tabbed().query(TabPane) if pane.id]

    def action_next_tab(self) -> None:
        tabbed = self._tabbed()
        order = self._tab_order()
        if not order:
            return
        try:
            index = order.index(tabbed.active)
        except ValueError:
            index = -1
        tabbed.active = order[(index + 1) % len(order)]

    def action_previous_tab(self) -> None:
        tabbed = self._tabbed()
        order = self._tab_order()
        if not order:
            return
        try:
            index = order.index(tabbed.active)
        except ValueError:
            index = 0
        tabbed.active = order[(index - 1) % len(order)]

    def on_mount(self) -> None:
        self._place_progress()

    def on_resize(self, event: Resize) -> None:
        self._place_progress()

    def _place_progress(self) -> None:
        """Move the progress box to its best spot in TUI, guarded against races"""
        if self._relocating:
            return
        self._relocating = True
        self.run_worker(
            self._apply_progress_layout(),
            group=self._PROGRESS_GROUP,
            description="progress bar responsive placement",
            exit_on_error=False,
        )

    async def _apply_progress_layout(self) -> None:
        try:
            await self._apply_progress_layout_once()
        finally:
            self._relocating = False

    async def _apply_progress_layout_once(self) -> None:
        toolbar = self.query_one("#toolbar")
        area = self.query_one("#toolbar_area")
        box = self.query_one("#progress_box", ProgressBox)
        inline = self._toolbar_fits_inline(toolbar)
        in_toolbar = box in toolbar.children
        if not in_toolbar and box.parent is not area:
            # box is detached, park it back before deciding, so it is never left outside the TUI DOM
            await area.mount(box)
            in_toolbar = False
        if inline == in_toolbar:
            return
        await box.remove()
        if inline:
            toolbar.mount(box, after=self.query_one("#exec_btn"))
        else:
            area.mount(box)
        box.set_class(inline, "inline")

    def _toolbar_fits_inline(self, toolbar) -> bool:
        """Whether the toolbar row can host the inline progress box."""
        used = 0
        for child in toolbar.children:
            if getattr(child, "id", None) == "progress_box":
                continue
            if isinstance(child, Static) and "spacer" in child.classes:
                continue
            used += child.outer_size.width + 1
        if used <= 0:
            return self.screen.size.width >= self._PROGRESS_MIN_WIDE_TERMINAL
        return toolbar.size.width >= used + self._PROGRESS_INLINE_WIDTH

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "local_btn":
            event.stop()
            self.tui.scan_controller.start_local()
        elif event.button.id == "feeds_btn":
            event.stop()
            self.tui.scan_controller.start_feeds()
        elif event.button.id == "full_btn":
            event.stop()
            self.tui.scan_controller.start_recon()
        elif event.button.id == "exec_btn":
            event.stop()
            self.tui.scan_controller.start_exec()
        elif event.button.id == "report_btn":
            event.stop()
            self.tui.report_controller.generate()
