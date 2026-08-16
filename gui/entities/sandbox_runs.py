"""Sandbox run TUI only model and parser for the execution-tests report"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class SandboxRun:
    """One sandbox PoC execution, ready for display"""

    cve_id: str = "N/A"
    execution_success: bool = False
    crashed: bool = False
    exit_code: int | None = None
    sandbox_platform: str = "unknown"
    run_timestamp: str = ""
    exploit_file_hash: str = ""
    url: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    modules: list[str] = field(default_factory=list)
    kernel_info: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    open_processes: list[str] = field(default_factory=list)
    open_files: list[str] = field(default_factory=list)

    @classmethod
    def from_exec_report(cls, report: dict[str, Any]) -> list[SandboxRun]:
        """Extract sandbox runs from the current execution report.

        Every PoC outcome becomes a row: successful/errored VM runs and the
        compile/build/sandbox failures that never reached a VM (they must be
        visible in the TUI, not only in the logs).
        """
        runs: list[SandboxRun] = []
        for entry in report.get("entries", []):
            cve_id = entry.get("cve_id", "N/A")
            for poc in entry.get("pocs", []):
                sbx = poc.get("sandbox")
                if not isinstance(sbx, dict):
                    error = poc.get("sandbox_error") or (
                        "PoC produced no sandbox outcome"
                    )
                    runs.append(
                        cls(
                            cve_id=cve_id,
                            execution_success=False,
                            crashed=False,
                            exit_code=None,
                            sandbox_platform=(
                                "compile" if "compile" in str(error).lower() else "error"
                            ),
                            run_timestamp=datetime.now(UTC).isoformat(),
                            url=poc.get("url") or "",
                            command=poc.get("test_cmd") or "",
                            stdout="",
                            stderr=str(error),
                        )
                    )
                    continue
                logs = sbx.get("logs", {}) or {}
                runs.append(
                    cls(
                        cve_id=cve_id,
                        execution_success=sbx.get("success", False),
                        crashed=sbx.get("crashed", False),
                        exit_code=sbx.get("returncode"),
                        sandbox_platform=sbx.get("mode", "unknown"),
                        run_timestamp=datetime.now(UTC).isoformat(),
                        exploit_file_hash=logs.get("exploit_hash", logs.get("binary", "")) or "",
                        url=poc.get("url") or "",
                        command=logs.get("command") or "",
                        stdout=sbx.get("stdout", ""),
                        stderr=sbx.get("stderr", ""),
                        modules=list(sbx.get("modules", []) or []),
                        kernel_info=sbx.get("kernel_info", {}) or {},
                        resources=sbx.get("resources", {}) or {},
                        open_processes=list(sbx.get("processes", []) or []),
                        open_files=list(sbx.get("files", []) or []),
                    )
                )
        return runs


__all__ = ["SandboxRun"]