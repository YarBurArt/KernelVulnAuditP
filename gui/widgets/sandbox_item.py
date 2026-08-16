"""Collapsible sandbox-run row for TUI

The header identifies the CVE, the severity and the run summary; the expanded
body shows the kernel/resources summary, colorized lists and the labeled
STDOUT/STDERR of the PoC itself.
"""

from __future__ import annotations

from typing import Any

from textual.widgets import Collapsible, Static

from gui.entities.sandbox_runs import SandboxRun
from gui.shared.colors import CRIT, OK, WARN
from gui.shared.formatting import (
    binary_output,
    first_resource_line,
    format_kernel_line,
    format_run_timestamp,
    is_url,
    markup_escape,
    short_hash,
)
from gui.widgets.colorized_list import ColorizedList


class SandboxItem(Collapsible):
    """A sandbox PoC execution: CVE + status row, then details + IO."""

    def __init__(self, run: SandboxRun, *args, **kwargs) -> None:
        self._run = run
        children = self._body(run)
        super().__init__(
            *args, *children, title=self._header(run), collapsed=True, **kwargs
        )

    @staticmethod
    def _status_text(run: SandboxRun) -> str:
        if run.crashed:
            return "CRASH"
        if run.execution_success:
            return f"SUCCESS (exit: {run.exit_code})"
        if run.exit_code == 0:
            return "COMPLETED WITH WARNINGS"
        if run.sandbox_platform in ("error", "compile"):
            return "FAILED"
        if run.exit_code is not None:
            return f"MAYBE (exit: {run.exit_code})"
        return "MAYBE"

    @staticmethod
    def _header(run: SandboxRun) -> str:
        if run.crashed:
            severity, color = "CRASH", CRIT
        elif run.execution_success:
            severity, color = "OK", OK
        else:
            severity, color = "FAIL", WARN
        sev = markup_escape(f"[{severity}]").ljust(7)
        cve = markup_escape(f"[{run.cve_id}]").ljust(16)
        platform = markup_escape(f"[{run.sandbox_platform}]").ljust(10)
        ts = markup_escape(format_run_timestamp(run.run_timestamp)).ljust(8)
        if run.sandbox_platform in ("error", "compile"):
            reason = " ".join(str(run.stderr).split())
            if len(reason) > 56:
                reason = reason[:56] + "…"
            return (
                f"[bold {color}]{sev}[/] "
                f"[dim]{cve}[/] "
                f"[dim]{platform}[/] "
                f"[dim]{markup_escape(reason)}[/] "
                f"{ts}"
            )
        exit_part = ""
        if run.exit_code is not None:
            exit_part = f"exit:{run.exit_code}".ljust(8)
        hash_part = ""
        if run.exploit_file_hash and not is_url(run.exploit_file_hash):
            hash_part = f"{markup_escape(short_hash(run.exploit_file_hash))} "
        io = f"stdout:{len(run.stdout)} stderr:{len(run.stderr)}"
        return (
            f"[bold {color}]{sev}[/] "
            f"[dim]{cve}[/] "
            f"[dim]{platform}[/] "
            f"[dim]{exit_part}[/] "
            f"{hash_part}"
            f"{ts} "
            f"{io}"
        )

    @staticmethod
    def _body(run: SandboxRun) -> list[Any]:
        children: list[Any] = []
        if run.sandbox_platform in ("error", "compile"):
            # a failure that never reached a VM (compile/build/sandbox error)
            children.append(
                Static(
                    f"Status: {SandboxItem._status_text(run)} — "
                    f"{markup_escape(run.stderr)}",
                    classes="mono terminal-fail",
                )
            )
            if run.url:
                children.append(
                    Static(f"PoC: {markup_escape(run.url)}", classes="mono")
                )
            if run.command:
                children.append(
                    Static(f"Command: {markup_escape(run.command)}", classes="mono")
                )
            return children
        status = SandboxItem._status_text(run)
        children.append(
            Static(
                f"Status: {markup_escape(status)} | "
                f"platform: {markup_escape(run.sandbox_platform)}",
                classes="mono",
            )
        )
        if run.command:
            children.append(
                Static(f"Command: {markup_escape(run.command)}", classes="mono")
            )
        if run.exploit_file_hash and not is_url(run.exploit_file_hash):
            children.append(
                Static(
                    f"Exploit file: {markup_escape(run.exploit_file_hash)}",
                    classes="mono",
                )
            )
        if run.url:
            children.append(Static(f"PoC: {markup_escape(run.url)}", classes="mono"))
        if run.kernel_info:
            children.append(
                Static(
                    f"Kernel: {markup_escape(format_kernel_line(run.kernel_info))}",
                    classes="mono",
                )
            )
        if run.resources:
            mem = first_resource_line(run.resources.get("meminfo"))
            if mem:
                children.append(Static(f"Memory: {markup_escape(mem)}", classes="mono"))
            cpu = first_resource_line(run.resources.get("cpuinfo"))
            if cpu:
                children.append(Static(f"CPU: {markup_escape(cpu)}", classes="mono"))
        if run.modules:
            children.append(
                Static("Modules", classes="mono-bold section-label")
            )
            children.append(ColorizedList(run.modules, "modules"))
        if run.open_processes:
            children.append(
                Static("Processes", classes="mono-bold section-label")
            )
            children.append(ColorizedList(run.open_processes, "process"))
        if run.open_files:
            children.append(Static("Files", classes="mono-bold section-label"))
            children.append(ColorizedList(run.open_files, "file"))
        if run.stdout:
            children.append(
                Static(
                    f"STDOUT:\n{markup_escape(binary_output(run.stdout))}",
                    classes="mono terminal-view",
                )
            )
        if run.stderr:
            children.append(
                Static(
                    f"STDERR:\n{markup_escape(run.stderr)}",
                    classes="mono terminal-fail",
                )
            )
        return children
