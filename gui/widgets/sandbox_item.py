"""Collapsible sandbox-run row for TUI

The header identifies the CVE, the severity and the run summary; the expanded
body shows the kernel/resources summary, colorized lists and the labeled
STDOUT/STDERR of the PoC itself.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from textual.widgets import Collapsible, Static

from core.entities import PocExecution
from gui.shared.colors import CRIT, OK, WARN
from gui.shared.formatting import (
    binary_output,
    first_resource_line,
    format_kernel_line,
    is_url,
    markup_escape,
    short_hash,
)
from gui.widgets.colorized_list import ColorizedList
from presentation.glyphs import unicode_glyph


class SandboxItem(Collapsible):
    """A sandbox PoC execution: CVE + status row, then details + IO."""

    def __init__(self, cve_id: str, poc: PocExecution, *args, **kwargs) -> None:
        self._cve_id = cve_id
        self._poc = poc
        children = self._body()
        super().__init__(
            *args,
            *children,
            title=self._header(),
            collapsed=True,
            collapsed_symbol=unicode_glyph("▶", ">"),
            expanded_symbol=unicode_glyph("▼", "v"),
            **kwargs,
        )

    @property
    def _sandbox(self):
        return self._poc.sandbox

    @property
    def cve_id(self) -> str:
        return self._cve_id

    @property
    def success(self) -> bool:
        return self._success

    @property
    def _error(self) -> str:
        return self._poc.sandbox_error or "PoC produced no sandbox outcome"

    @property
    def _platform(self) -> str:
        if self._sandbox is not None:
            return self._sandbox.execution_mode
        return "compile" if "compile" in self._error.lower() else "error"

    @property
    def _exit_code(self) -> int | None:
        return self._sandbox.returncode if self._sandbox is not None else None

    @property
    def _success(self) -> bool:
        return self._sandbox.success if self._sandbox is not None else False

    @property
    def _crashed(self) -> bool:
        return self._sandbox.crashed if self._sandbox is not None else False

    @property
    def _stdout(self) -> str:
        return self._sandbox.stdout if self._sandbox is not None else ""

    @property
    def _stderr(self) -> str:
        if self._sandbox is not None:
            return self._sandbox.stderr
        return self._error

    @property
    def _command(self) -> str:
        if self._sandbox is not None:
            return self._sandbox.logs.command or ""
        return self._poc.test_cmd or ""

    @property
    def _exploit_hash(self) -> str:
        if self._sandbox is not None:
            return self._sandbox.logs.binary or ""
        return ""

    @property
    def _kernel_info(self) -> dict[str, Any]:
        if self._sandbox is None:
            return {}
        return asdict(self._sandbox.kernel_info)

    @property
    def _resources(self) -> dict[str, Any]:
        if self._sandbox is None:
            return {}
        return asdict(self._sandbox.resources)

    @property
    def _modules(self) -> list[str]:
        return self._sandbox.modules if self._sandbox is not None else []

    @property
    def _processes(self) -> list[str]:
        return self._sandbox.processes if self._sandbox is not None else []

    @property
    def _files(self) -> list[str]:
        return self._sandbox.files if self._sandbox is not None else []

    def _status_text(self) -> str:
        if self._crashed:
            return "CRASH"
        if self._success:
            return f"SUCCESS (exit: {self._exit_code})"
        if self._exit_code == 0:
            return "COMPLETED WITH WARNINGS"
        if self._platform in ("error", "compile"):
            return "FAILED"
        if self._exit_code is not None:
            return f"MAYBE (exit: {self._exit_code})"
        return "MAYBE"

    def _header(self) -> str:
        if self._crashed:
            severity, color = "CRASH", CRIT
        elif self._success:
            severity, color = "OK", OK
        else:
            severity, color = "FAIL", WARN
        sev = markup_escape(f"[{severity}]").ljust(7)
        cve = markup_escape(f"[{self._cve_id}]").ljust(16)
        platform = markup_escape(f"[{self._platform}]").ljust(10)
        if self._platform in ("error", "compile"):
            reason = " ".join(str(self._stderr).split())
            if len(reason) > 56:
                reason = reason[:56] + unicode_glyph("…", "...")
            return (
                f"[bold {color}]{sev}[/] "
                f"[dim]{cve}[/] "
                f"[dim]{platform}[/] "
                f"[dim]{markup_escape(reason)}[/]"
            )
        exit_part = ""
        if self._exit_code is not None:
            exit_part = f"exit:{self._exit_code}".ljust(8)
        hash_part = ""
        if self._exploit_hash and not is_url(self._exploit_hash):
            hash_part = f"{markup_escape(short_hash(self._exploit_hash))} "
        io = f"stdout:{len(self._stdout)} stderr:{len(self._stderr)}"
        return (
            f"[bold {color}]{sev}[/] "
            f"[dim]{cve}[/] "
            f"[dim]{platform}[/] "
            f"[dim]{exit_part}[/] "
            f"{hash_part}"
            f"{io}"
        )

    def _body(self) -> list[Any]:
        children: list[Any] = []
        if self._platform in ("error", "compile"):
            # a failure that never reached a VM (compile/build/sandbox error)
            children.append(
                Static(
                    f"Status: {self._status_text()} "
                    f"{unicode_glyph('—', '-')} "
                    f"{markup_escape(self._stderr)}",
                    classes="mono terminal-fail",
                )
            )
            if self._poc.url:
                children.append(
                    Static(f"PoC: {markup_escape(self._poc.url)}", classes="mono")
                )
            if self._command:
                children.append(
                    Static(f"Command: {markup_escape(self._command)}", classes="mono")
                )
            return children
        status = self._status_text()
        children.append(
            Static(
                f"Status: {markup_escape(status)} | "
                f"platform: {markup_escape(self._platform)}",
                classes="mono",
            )
        )
        if self._command:
            children.append(
                Static(f"Command: {markup_escape(self._command)}", classes="mono")
            )
        if self._exploit_hash and not is_url(self._exploit_hash):
            children.append(
                Static(
                    f"Exploit file: {markup_escape(self._exploit_hash)}",
                    classes="mono",
                )
            )
        if self._poc.url:
            children.append(
                Static(f"PoC: {markup_escape(self._poc.url)}", classes="mono")
            )
        if self._kernel_info:
            children.append(
                Static(
                    f"Kernel: {markup_escape(format_kernel_line(self._kernel_info))}",
                    classes="mono",
                )
            )
        if self._resources:
            mem = first_resource_line(self._resources.get("meminfo"))
            if mem:
                children.append(Static(f"Memory: {markup_escape(mem)}", classes="mono"))
            cpu = first_resource_line(self._resources.get("cpuinfo"))
            if cpu:
                children.append(Static(f"CPU: {markup_escape(cpu)}", classes="mono"))
        if self._modules:
            children.append(
                Static("Modules", classes="mono-bold section-label")
            )
            children.append(ColorizedList(self._modules, "modules"))
        if self._processes:
            children.append(
                Static("Processes", classes="mono-bold section-label")
            )
            children.append(ColorizedList(self._processes, "process"))
        if self._files:
            children.append(Static("Files", classes="mono-bold section-label"))
            children.append(ColorizedList(self._files, "file"))
        if self._stdout:
            children.append(
                Static(
                    f"STDOUT:\n{markup_escape(binary_output(self._stdout))}",
                    classes="mono terminal-view",
                )
            )
        if self._stderr:
            children.append(
                Static(
                    f"STDERR:\n{markup_escape(self._stderr)}",
                    classes="mono terminal-fail",
                )
            )
        return children