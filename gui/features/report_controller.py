"""Report generation controller"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gui.shared.errors import APP_ERRORS

if TYPE_CHECKING:
    from gui.tui import KernelVulnTUI

logger = logging.getLogger("kernel_audit.gui")


class ReportController:
    """Runs the report build off the TUI thread and streams its output concurrently"""

    def __init__(self, app: KernelVulnTUI) -> None:
        self._app = app
        self._lines: list[str] = []

    @property
    def lines(self) -> list[str]:
        return list(self._lines)

    def generate(self) -> None:
        """report generation in the background"""
        self._lines.clear()
        self._emit("Launching report generation...\n")
        self._app.run_task(self._build, self._on_done, self._on_error)

    def _build(self) -> list[str]:
        """Run in a worker thread; returns the lines to append, need for streamlit process"""
        report_path = Path(__file__).resolve().parent.parent.parent / "report.py"
        if not report_path.exists():
            raise FileNotFoundError("report.py not found")

        try:
            import streamlit  # type: ignore[import-not-found]  # noqa: F401
        except ImportError:
            return ["Streamlit not available, running CLI report...\n"] + [
                self._run_cli_report_sync()
            ]
        else:
            subprocess.Popen(
                [sys.executable, "-m", "streamlit", "run", str(report_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return [
                "Launching Streamlit report...\n",
                "Streamlit report launched at http://localhost:8501\n",
                "or next port if already taken.",
            ]

    @staticmethod
    def _run_cli_report_sync() -> str:
        try:
            from db import get_db
            from report import CLIReportRenderer, build_report_data

            db = get_db("orm")
            try:
                data = build_report_data(db)
            finally:
                db.close()

            renderer = CLIReportRenderer(data, verbose=True)
            return renderer.build_full_report() + "\nReport generated (CLI mode)\n"
        except APP_ERRORS as exc:
            # only for Engine-stdout tab instead of being hidden by the error line
            logger.exception("CLI report generation failed")
            return f"CLI report error: {exc}\n"

    def _on_done(self, lines: list[str] | None) -> None:
        for line in lines or []:
            self._emit(line)

    def _on_error(self, exc: Any) -> None:
        self._emit(f"Report error: {exc}\n")
        self._emit(self._run_cli_report_sync())

    def _emit(self, text: str) -> None:
        self._lines.append(text)
        self._app.append_report(text)