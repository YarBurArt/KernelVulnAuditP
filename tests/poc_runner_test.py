import subprocess
from pathlib import Path

import pytest

from core.entities import SandboxRunResult
from isolate.poc_runner import PoCRunner, compile_poc, resolve_poc_binary


class _FakeIsolate:
    """Stand-in sandbox: run_binary returns whatever was configured."""

    def __init__(self, result):
        self.result = result

    def run_binary(self, binary):
        return self.result


def _ok_run(*args, **kwargs):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")


def _executable(tmp_path, name="poc") -> Path:
    binary = tmp_path / name
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    return binary


def test_runner_skips_without_commands(tmp_path):
    runner = PoCRunner(_FakeIsolate(None))
    outcome = runner.run(tmp_path, "", "")
    assert outcome.sandbox is None
    assert outcome.error is None


def test_runner_compile_failure(tmp_path, monkeypatch):
    def failing_run(*args, **kwargs):
        raise RuntimeError("rc=1: gcc error")

    monkeypatch.setattr("isolate.poc_runner.run_cmd", failing_run)
    runner = PoCRunner(_FakeIsolate(None))
    outcome = runner.run(tmp_path, "gcc x.c", "./x")
    assert outcome.error == "compile failed: rc=1: gcc error"


def test_runner_compile_nonzero_rc(tmp_path, monkeypatch):
    def nonzero_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="gcc error"
        )

    monkeypatch.setattr("isolate.poc_runner.run_cmd", nonzero_run)
    runner = PoCRunner(_FakeIsolate(None))
    outcome = runner.run(tmp_path, "gcc x.c", "./x")
    assert "compile failed" in outcome.error


def test_runner_no_executable(tmp_path, monkeypatch):
    monkeypatch.setattr("isolate.poc_runner.run_cmd", _ok_run)
    runner = PoCRunner(_FakeIsolate(None))
    outcome = runner.run(tmp_path, "gcc x.c", None)
    assert outcome.error == "no executable produced by the PoC build"


def test_runner_no_backend_available(tmp_path, monkeypatch):
    monkeypatch.setattr("isolate.poc_runner.run_cmd", _ok_run)
    _executable(tmp_path)
    runner = PoCRunner(_FakeIsolate(None))
    outcome = runner.run(tmp_path, "true", "./poc")
    assert "no sandbox backend" in outcome.error


def test_runner_sandbox_success(tmp_path, monkeypatch):
    monkeypatch.setattr("isolate.poc_runner.run_cmd", _ok_run)
    _executable(tmp_path)
    result = SandboxRunResult(
        returncode=0,
        execution_mode="qemu",
        crashed=False,
        stdout="ok",
        stderr="",
        duration_ms=1.0,
    )
    runner = PoCRunner(_FakeIsolate(result))
    outcome = runner.run(tmp_path, "true", "./poc")
    assert outcome.sandbox is result
    assert outcome.command == "./poc"


def test_runner_sandbox_raises(tmp_path, monkeypatch):
    monkeypatch.setattr("isolate.poc_runner.run_cmd", _ok_run)
    _executable(tmp_path)

    class _RaisingIsolate:
        def run_binary(self, binary):
            raise RuntimeError("vm crashed")

    runner = PoCRunner(_RaisingIsolate())
    outcome = runner.run(tmp_path, "true", "./poc")
    assert outcome.error == "vm crashed"


def test_compile_poc_success(tmp_path, monkeypatch):
    monkeypatch.setattr("isolate.poc_runner.run_cmd", _ok_run)
    compile_poc(tmp_path, "gcc a.c")


def test_compile_poc_failure_raises(tmp_path, monkeypatch):
    def nonzero_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="gcc error"
        )

    monkeypatch.setattr("isolate.poc_runner.run_cmd", nonzero_run)
    with pytest.raises(RuntimeError, match="rc=1"):
        compile_poc(tmp_path, "gcc a.c")


def test_compile_poc_timeout_raises(tmp_path, monkeypatch):
    def timeout_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["gcc"], timeout=5, output="partial", stderr=""
        )

    monkeypatch.setattr("isolate.poc_runner.run_cmd", timeout_run)
    with pytest.raises(RuntimeError, match="compile timed out"):
        compile_poc(tmp_path, "gcc a.c")


def test_compile_poc_musl_gcc_rewrites_direct_cmd(tmp_path, monkeypatch):
    import shutil

    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs)
        captured["cmd_arg"] = args[0]
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(
        shutil,
        "which",
        lambda n: "/usr/bin/musl-gcc" if n == "musl-gcc" else "/usr/bin/gcc",
    )
    monkeypatch.setattr("isolate.poc_runner.run_cmd", capture_run)

    compile_poc(tmp_path, "gcc x.c -o poc")
    assert captured["cmd_arg"] == "musl-gcc x.c -o poc -static"
    assert captured["env"]["REALGCC"] == "/usr/bin/gcc"


def test_compile_poc_musl_gcc_non_direct_cmd_sets_cc(tmp_path, monkeypatch):
    import shutil

    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(
        shutil,
        "which",
        lambda n: "/usr/bin/musl-gcc" if n == "musl-gcc" else "/usr/bin/gcc",
    )
    monkeypatch.setattr("isolate.poc_runner.run_cmd", capture_run)

    compile_poc(tmp_path, "make all")
    assert "CC" in captured["env"]
    assert "musl-gcc" in captured["env"]["CC"]


def test_compile_poc_musl_gcc_no_real_gcc_skips_realgcc(tmp_path, monkeypatch):
    import shutil

    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(
        shutil,
        "which",
        lambda n: "/usr/bin/musl-gcc" if n == "musl-gcc" else None,
    )
    monkeypatch.setattr("isolate.poc_runner.run_cmd", capture_run)

    compile_poc(tmp_path, "gcc x.c")
    assert "REALGCC" not in captured["env"]


def test_compile_poc_no_musl_gcc_passes_cmd_through(tmp_path, monkeypatch):
    import shutil

    captured = {}

    def capture_run(*args, **kwargs):
        captured.update(kwargs)
        captured["cmd_arg"] = args[0]
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(shutil, "which", lambda n: None)
    monkeypatch.setattr("isolate.poc_runner.run_cmd", capture_run)

    compile_poc(tmp_path, "make all")
    assert captured["cmd_arg"] == "make all"
    assert "musl-gcc" not in captured.get("env", {}).get("PATH", "")


def test_resolve_poc_binary_from_test_cmd(tmp_path):
    binary = _executable(tmp_path, "prog")
    resolved = resolve_poc_binary(tmp_path, "./prog", "gcc a.c")
    assert resolved == binary.resolve()


def test_resolve_poc_binary_from_compile_o(tmp_path):
    binary = tmp_path / "out"
    binary.write_text("x")
    binary.chmod(0o755)
    resolved = resolve_poc_binary(tmp_path, None, "gcc a.c -o out")
    assert resolved == binary.resolve()


def test_resolve_poc_binary_compile_cmd_no_o(tmp_path):
    (tmp_path / "src.c").write_text("x")
    assert resolve_poc_binary(tmp_path, None, "gcc a.c -O2") is None


def test_resolve_poc_binary_test_cmd_no_slash(tmp_path):
    (tmp_path / "src.c").write_text("x")
    assert resolve_poc_binary(tmp_path, "python x.py", "gcc a.c -o out") is None


def test_resolve_poc_binary_gcc_aout(tmp_path):
    binary = tmp_path / "a.out"
    binary.write_text("x")
    binary.chmod(0o755)
    resolved = resolve_poc_binary(tmp_path, None, "gcc a.c")
    assert resolved == binary.resolve()


def test_resolve_poc_binary_falls_back_newest_executable(tmp_path):
    (tmp_path / "gen.c").write_text("x")
    newest = tmp_path / "newbin"
    newest.write_text("x")
    newest.chmod(0o755)
    resolved = resolve_poc_binary(tmp_path, None, None)
    assert resolved == newest.resolve()


def test_resolve_poc_binary_no_executable(tmp_path):
    (tmp_path / "src.c").write_text("x")
    assert resolve_poc_binary(tmp_path, None, None) is None


def test_resolve_poc_binary_name_not_executable(tmp_path):
    named = tmp_path / "prog"
    named.write_text("not executable")
    named.chmod(0o644)
    fallback = tmp_path / "fallback"
    fallback.write_text("x")
    fallback.chmod(0o755)
    resolved = resolve_poc_binary(tmp_path, "./prog", None)
    assert resolved == fallback.resolve()


def test_resolve_poc_binary_oserror_on_iterdir(tmp_path):
    somefile = tmp_path / "f"
    somefile.write_text("x")
    assert resolve_poc_binary(somefile, None, None) is None
