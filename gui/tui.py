"""Textual TUI entry point"""

from __future__ import annotations

import logging
import threading  # >= 3.14t
from collections.abc import Callable
from typing import Any, ClassVar

from textual.app import App
from textual.containers import VerticalScroll
from textual.css.query import NoMatches, QueryType
from textual.screen import Screen
from textual.widget import Widget

from gui.entities.progress import ProgressAdapter
from gui.entities.services import Services
from gui.features.report_controller import ReportController
from gui.features.scan_controller import ScanController
from gui.pages.scan_page import ScanPage
from gui.shared.log_bridge import TUIHandler
from gui.widgets.console_log import ConsoleLog
from gui.widgets.metrics_bar import MetricsBar
from gui.widgets.progress_box import ProgressBox
from gui.widgets.stages_panel import StagesPanel, stage_for_label

GUI_E = True

logger = logging.getLogger("kernel_audit.gui")

_LOG_LEVEL_MAP = {
    "FAIL": logging.ERROR,
    "WARN": logging.WARNING,
    "OK": logging.INFO,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


class KernelVulnTUI(App[str]):
    """The Textual application (single scan page + report in Engine stdout).
    long-running flows run off the UI thread and marshal results back, and the shared
    widgets (console, stages, progress) are updated only from the UI thread.
    """

    TITLE = "Kernel Vulnerability Auditor"
    SUB_TITLE = "Kernel / PoC security audit"
    CSS_PATH = "style.tcss"

    SCREENS: ClassVar[dict[str, Callable[[], Screen]]] = {
        "scan": ScanPage,
    }

    def __init__(self, db, **kwargs) -> None:
        super().__init__(**kwargs)
        self.services = Services(db=db, progress=self._make_progress_bar)
        self.scan_controller = ScanController(self, self.services)
        self.report_controller = ReportController(self)
        self._counters = {"crit": 0, "warn": 0, "cve": 0, "runs": 0}
        self._tui_handler: TUIHandler | None = None

    def on_mount(self) -> None:
        self.push_screen("scan")
        self._attach_logger()

    def on_unmount(self) -> None:
        logger_local = logging.getLogger("kernel_audit")
        if self._tui_handler is not None:
            logger_local.removeHandler(self._tui_handler)
            self._tui_handler = None

    def _attach_logger(self) -> None:
        """Route the kernel_audit logger into the Engine-stdout console."""
        logger_local = logging.getLogger("kernel_audit")
        self._tui_handler = TUIHandler(self)
        assert self._tui_handler is not None
        logger_local.addHandler(self._tui_handler)
        # other loggers (httpx, sqlalchemy, ...) would otherwise fall
        # through to the stderr lastResort handler and corrupt the TUI screen
        root = logging.getLogger()
        if not any(isinstance(h, logging.NullHandler) for h in root.handlers):
            root.addHandler(logging.NullHandler())

    def run_task(
        self,
        fn: Callable[[], Any],
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        """Run fn in a daemon thread, marshaling the result back to the UI."""

        def _worker() -> None:
            try:
                result = fn()
            except Exception as exc:
                # Always keep the full traceback in the log
                logger.exception("Background task %r failed", fn)
                if on_error is not None:
                    self.call_from_thread(self._dispatch, on_error, exc)
            else:
                if on_done is not None:
                    self.call_from_thread(self._dispatch, on_done, result)

        threading.Thread(target=_worker, name="gui-task", daemon=True).start()

    @staticmethod
    def _dispatch(callback: Callable[[Any], None], value: Any) -> None:
        callback(value)

    def _make_progress_bar(self, total: int = 0, label: str = "") -> ProgressAdapter:
        return ProgressAdapter(
            self.get_progress_box(),
            marshal=self.call_from_thread,
            total=total,
            label=label,
            on_label=self._on_stage_progress,
        )

    def _on_stage_progress(self, label: str, final: bool, note: str = "") -> None:
        """Keep the big-stages checklist sub-steps in sync."""
        panel = self.get_stages_panel()
        if panel is None:
            return
        key = stage_for_label(label)
        if key is None:
            return
        if final:
            panel.finish_stage(key, label)
            if note:
                panel.set_stage_summary(key, note)
        else:
            panel.set_running(key, label, note)

    def get_scan_list(self, name: str) -> VerticalScroll:
        return self.get_screen("scan").query_one(f"#{name}", VerticalScroll)

    def _scan_widget(
        self, query: str | type[QueryType], widget_type: type[QueryType | Widget] | None = None
    ) -> Any | None:
        """The scan-screen widget for query, or None before it is mounted."""
        if not self.is_screen_installed("scan"):
            return None
        try:
            screen = self.get_screen("scan")
            if widget_type is None:
                return screen.query_one(query)
            return screen.query_one(query, widget_type)
        except NoMatches:
            return None

    def get_console(self) -> ConsoleLog | None:
        return self._scan_widget("#console_log", ConsoleLog)

    def get_metrics_bar(self) -> MetricsBar | None:
        return self._scan_widget(MetricsBar)

    def get_progress_box(self) -> ProgressBox | None:
        return self._scan_widget(ProgressBox)

    def get_stages_panel(self) -> StagesPanel | None:
        return self._scan_widget(StagesPanel)

    def set_stage(self, key: str, status: str) -> None:
        panel = self.get_stages_panel()
        if panel is not None:
            panel.set_stage(key, status)

    def set_stage_detail(self, key: str, detail: str, note: str = "") -> None:
        panel = self.get_stages_panel()
        if panel is not None:
            panel.set_running(key, detail, note)

    def set_stage_summary(self, key: str, summary: str) -> None:
        panel = self.get_stages_panel()
        if panel is not None:
            panel.set_stage_summary(key, summary)

    def log_terminal(self, message: str, level: str = "INFO") -> None:
        console = self.get_console()
        if console is not None:
            console.log_line(message, level)
        logger_local = logging.getLogger("kernel_audit.gui")
        levelno = _LOG_LEVEL_MAP.get(level, logging.INFO)
        logger_local.log(levelno, message, extra={"skip_console": True})

    def append_report(self, text: str) -> None:
        console = self.get_console()
        if console is not None:
            console.write_raw(text)

    def show_progress(self, label: str = "") -> None:
        box = self.get_progress_box()
        if box is not None:
            box.show(label)

    def hide_progress(self) -> None:
        box = self.get_progress_box()
        if box is not None:
            box.hide()

    def set_metrics(
        self,
        crit: int | None = None,
        warn: int | None = None,
        cve: int | None = None,
        runs: int | None = None,
    ) -> None:
        for key, value in (("crit", crit), ("warn", warn), ("cve", cve), ("runs", runs)):
            if value is not None:
                self._counters[key] = value
        bar = self.get_metrics_bar()
        if bar is not None:
            bar.update_counts(**self._counters)
