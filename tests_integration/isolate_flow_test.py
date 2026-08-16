"""Integration tests for the sandbox execution flow.

These exercise real behavior that the unit tests fake out: the 120s-workaround
replacements (tree-kill on timeout, partial-output capture, guest exit-code
propagation, guest markers) and the TUI-side contracts (compile/sandbox
failures must surface in the SandboxRun model, long console lines must not
crash Textual, stage descriptions + headline sub-step dedup).

Real virtme-ng runs are included but skipped when the tool is unavailable.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

import pytest

from isolate.isolate import run_cmd


def _require_pgrep():
    if not shutil_which("pgrep"):
        pytest.skip("pgrep unavailable")


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


@pytest.mark.integration
def test_run_cmd_timeout_kills_whole_process_tree():
    """A timeout must SIGKILL the whole session/process-group, not just the
    direct child (the original 120s-workaround left orphaned compilers)."""
    _require_pgrep()
    with pytest.raises(subprocess.TimeoutExpired):
        run_cmd(
            ["sh", "-c", "sleep 120 & sleep 120 & sleep 120 & wait"],
            timeout=1,
            capture_output=True,
            text=True,
        )
    time.sleep(0.3)
    gone = subprocess.run(
        ["pgrep", "-f", "sleep 120"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert gone.returncode != 0, "orphaned sleep processes survived the timeout"


@pytest.mark.integration
def test_run_cmd_timeout_captures_partial_output():
    """Output produced before the timeout must survive (used to build the
    'execution timeout' detail instead of a silent kill)."""
    with pytest.raises(subprocess.TimeoutExpired) as ei:
        run_cmd(
            ["sh", "-c", "echo partial-progress; sleep 30"],
            timeout=1,
            capture_output=True,
            text=True,
        )
    out = ei.value.output or ""
    assert "partial-progress" in out


@pytest.mark.integration
def test_virtme_ng_guest_markers_and_exit_code(tmp_path):
    """Real virtme-ng run: BINARY OUTPUT markers delimit the PoC output and
    the guest's own EXIT_CODE is propagated as the execution returncode."""
    from isolate.virtme_ng_vm import VirtmeNGEnvironment

    if not shutil_which("virtme-ng"):
        pytest.skip("virtme-ng unavailable")

    source = tmp_path / "exit42.c"
    source.write_text("int main(void){return 42;}\n")

    compiler = _compile(source)
    binary = compiler.compile()
    assert binary and binary.exists()

    env = VirtmeNGEnvironment(binary, timeout=240, memory_mb=512, cpus=1)
    result = env.execute()

    assert result.execution_mode == "virtme-ng"
    assert result.crashed is False
    assert result.returncode == 42
    assert result.logs["exit_code"] == "42"
    assert "========== BINARY OUTPUT START ==========" in result.stdout
    assert "========== BINARY OUTPUT END ==========" in result.stdout
    start = result.stdout.index("========== BINARY OUTPUT START ==========")
    end = result.stdout.index("========== BINARY OUTPUT END ==========")
    assert "EXIT_CODE=42" in result.stdout[start:end]


@pytest.mark.integration
def test_execute_poc_compile_failure_reports_sandbox_error(tmp_path):
    """A failing PoC compile is a legitimate outcome: it must surface as a
    sandbox_error row, not vanish from the report (the old TUI bug)."""
    from app_services import AppServices

    svc = AppServices.__new__(AppServices)
    poc = {
        "local_path": str(tmp_path),
        "compile_cmd": "false",
        "test_cmd": None,
        "url": "https://example.com/poc",
    }
    out = svc._execute_poc("CVE-2099-0001", poc)

    assert "sandbox" not in out
    assert "sandbox_error" in out
    assert "compile" in out["sandbox_error"]


@pytest.mark.integration
def test_execute_poc_sandbox_error_when_no_backend(tmp_path):
    """When the compile succeeds but no sandbox backend is available the
    outcome is a sandbox_error, so the TUI shows a failure row."""
    from app_services import AppServices

    class _FakeIsolate:
        def run_binary(self, binary):
            return None

    poc_binary = tmp_path / "poc"
    poc_binary.write_text("#!/bin/sh\necho hi\n")
    poc_binary.chmod(0o755)

    svc = AppServices.__new__(AppServices)
    svc.isolate = _FakeIsolate()
    poc = {
        "local_path": str(tmp_path),
        "compile_cmd": "true",
        "test_cmd": "./poc",
        "url": "https://example.com/poc",
    }
    out = svc._execute_poc("CVE-2099-0002", poc)

    assert "sandbox" not in out
    assert "sandbox_error" in out
    assert "no sandbox backend" in out["sandbox_error"]


@pytest.mark.integration
def test_from_exec_report_keeps_compile_and_sandbox_failures():
    """SandboxRun.from_exec_report must produce rows for PoCs that failed
    before or inside the sandbox, not only for successful VM runs."""
    from gui.entities.sandbox_runs import SandboxRun

    report = {
        "entries": [
            {
                "cve_id": "CVE-2099-0001",
                "pocs": [
                    {
                        "url": "https://example.com/a",
                        "sandbox_error": "compile failed: rc=1",
                    },
                    {
                        "url": "https://example.com/b",
                        "sandbox_error": "no sandbox backend available",
                    },
                    {
                        "url": "https://example.com/c",
                        "sandbox": {
                            "success": True,
                            "crashed": False,
                            "returncode": 0,
                            "mode": "virtme-ng",
                            "stdout": "POC_OK",
                            "stderr": "",
                            "logs": {"binary": "hash-x"},
                        },
                    },
                ],
            }
        ]
    }

    runs = SandboxRun.from_exec_report(report)

    assert len(runs) == 3
    ok = [r for r in runs if r.execution_success]
    failed = [r for r in runs if not r.execution_success]
    assert len(ok) == 1 and ok[0].stdout == "POC_OK"
    assert len(failed) == 2
    platforms = {r.sandbox_platform for r in failed}
    assert "compile" in platforms
    assert "error" in platforms
    assert all(r.stderr for r in failed)


@pytest.mark.integration
def test_stages_panel_renders_descriptions():
    """The stages checklist must show its per-stage descriptions and must not
    add a duplicate sub-step for headline progress labels."""
    import anyio
    from textual.app import App, ComposeResult

    from gui.widgets.stages_panel import _HEADLINE_LABELS, STAGES, StageRow, StagesPanel

    class _T(App[None]):
        def compose(self) -> ComposeResult:
            yield StagesPanel()

    async def main() -> None:
        app = _T()
        async with app.run_test() as pilot:
            await pilot.pause()
            panel = app.query_one(StagesPanel)
            rows = list(panel.query(StageRow))
            assert len(rows) == len(STAGES)
            for row, (_, name, description) in zip(rows, STAGES):
                assert name in str(row.render())
                assert description in str(row.render())
            assert _HEADLINE_LABELS  # non-empty dedup set

    anyio.run(main)


@pytest.mark.integration
def test_console_log_survives_multi_kilobyte_line():
    """A DEBUG dump several orders larger than the cap must render in the
    Textual console without hanging or raising."""
    import anyio
    from textual.app import App, ComposeResult

    from gui.widgets.console_log import ConsoleLog

    class _C(App[None]):
        def compose(self) -> ComposeResult:
            yield ConsoleLog()

    async def main() -> None:
        app = _C()
        async with app.run_test() as pilot:
            await pilot.pause()
            log = app.query_one(ConsoleLog)
            log.log_line("x" * 100_000, "DEBUG")
            log.write_raw("y" * 100_000)
            rendered = str(log.render())
            assert len(rendered) > 0

    anyio.run(main)


@pytest.mark.integration
def test_sandbox_error_row_header_has_no_exit_none_or_url_hash():
    """An error/compile row must not show 'exit:None' nor a truncated URL in
    the hash slot; the error reason, PoC URL and command belong in the body."""
    from gui.entities.sandbox_runs import SandboxRun
    from gui.widgets.sandbox_item import SandboxItem

    run = SandboxRun(
        cve_id="CVE-2021-22555",
        sandbox_platform="compile",
        stderr="compile failed: rc=1 gcc not found",
        url="https://github.com/org/CVE-2021-22555",
        command="gcc exploit.c",
    )

    header = SandboxItem._header(run)
    assert "exit:None" not in header
    assert "https://gith" not in header
    assert "compile failed: rc=1" in header

    body = [str(c.render()) for c in SandboxItem._body(run)]
    assert any("compile failed: rc=1" in line for line in body)
    assert any("https://github.com/org/CVE-2021-22555" in line for line in body)
    assert any("gcc exploit.c" in line for line in body)


@pytest.mark.integration
def test_sandbox_vm_row_shows_status_command_and_hash():
    """A successful VM run renders report-level detail: status text, platform,
    the real run command and the exploit file (not the URL)."""
    from gui.entities.sandbox_runs import SandboxRun
    from gui.widgets.sandbox_item import SandboxItem

    run = SandboxRun(
        cve_id="CVE-2022-2586",
        execution_success=True,
        exit_code=0,
        sandbox_platform="virtme-ng",
        exploit_file_hash="abc123def456",
        url="https://github.com/org/CVE-2022-2586",
        command="./exploit",
        stdout="POC_OK",
        stderr="",
    )

    header = SandboxItem._header(run)
    assert "exit:0" in header
    assert "abc123def456" in header
    assert "stdout:6" in header
    assert "https://gith" not in header

    body = [str(c.render()) for c in SandboxItem._body(run)]
    assert any("SUCCESS (exit: 0)" in line for line in body)
    assert any("platform: virtme-ng" in line for line in body)
    assert any("Command: ./exploit" in line for line in body)
    assert any("Exploit file: abc123def456" in line for line in body)


def _compile(source: Path):
    from isolate.isolate import CCompiler

    return CCompiler(source, source.parent)