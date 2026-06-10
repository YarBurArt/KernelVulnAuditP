# tests/test_isolate.py

import json
import subprocess
from pathlib import Path

import pytest

from isolate import ExecutionResult, QEMUEnvironment, HostEnvironment, CCompiler, Isolate


def test_execution_result_to_json():
    result = ExecutionResult(
        stdout="out",
        stderr="err",
        returncode=0,
        execution_mode="qemu",
        logs={"a": "b"},
        duration_ms=1.5,
        crashed=False,
    )

    data = json.loads(result.to_json())

    assert data["stdout"] == "out"
    assert data["stderr"] == "err"
    assert data["returncode"] == 0
    assert data["execution_mode"] == "qemu"
    assert data["crashed"] is False

def test_parse_qemu_output_basic():
    env = QEMUEnvironment(Path("/tmp/test"), 10)

    stdout = """
noise

=== BINARY OUTPUT START ===
hello
world
=== BINARY OUTPUT END ===

EXIT_CODE=7
"""

    out, err = env._parse_qemu_output(stdout, "")

    assert out == "hello\nworld"
    assert err == ""
    assert env.logs["exit_code"] == "7"


def test_parse_qemu_output_missing_end_marker():
    env = QEMUEnvironment(Path("/tmp/test"), 10)
    stdout = "\n=== BINARY OUTPUT START ===\nhello\nworld"

    out, _ = env._parse_qemu_output(stdout, "")

    assert out == "hello\nworld"
    assert env.logs["exit_code"] == "0"


def test_parse_qemu_output_no_markers():
    env = QEMUEnvironment(Path("/tmp/test"), 10)

    out, _ = env._parse_qemu_output("random noise", "")

    assert out == ""
    assert env.logs["exit_code"] == "0"

@pytest.mark.parametrize(
    "text",
    [
        "Kernel panic", "BUG:", "Oops:", "RIP:",
        "general protection fault", "segmentation fault",
    ],
)
def test_qemu_detect_crash(text):
    assert QEMUEnvironment._detect_crash(text) is True


def test_qemu_detect_crash_negative():
    assert QEMUEnvironment._detect_crash("hello world") is False

def test_qemu_execute_success(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = QEMUEnvironment(binary, 10)
    monkeypatch.setattr(QEMUEnvironment, "is_available", lambda self: True)

    monkeypatch.setattr(env, "_create_initrd", lambda path: None)
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(env, "_get_kernel_cmdline", lambda: "console=ttyS0")

    qemu_stdout = "noise\n=== BINARY OUTPUT START ===\nok_qemu\n=== BINARY OUTPUT END ===\nEXIT_CODE=42"
    completed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout=qemu_stdout, stderr=""
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)

    result = env.execute()

    assert result.returncode == 0
    assert result.stdout == "ok_qemu"
    assert result.crashed is False
    assert result.execution_mode == "qemu"
    assert result.logs["exit_code"] == "42"
    assert result.logs["stage"] == "vm_finished"


def test_qemu_execute_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = QEMUEnvironment(binary, 5)
    monkeypatch.setattr(QEMUEnvironment, "is_available", lambda self: True)

    monkeypatch.setattr(env, "_create_initrd", lambda path: None)
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(env, "_get_kernel_cmdline", lambda: "console=ttyS0")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["qemu"], timeout=5, output="partial", stderr="timeout"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = env.execute()

    assert result.returncode == -1
    assert result.crashed is True
    assert "Execution timeout (5s)" in result.stderr
    assert result.logs["timeout_stdout_size"] == "7"

def test_host_execute_success(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = HostEnvironment(binary)

    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="hello",
        stderr="",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: completed,
    )

    result = env.execute()

    assert result.returncode == 0
    assert result.stdout == "hello"
    assert result.crashed is False
    assert result.execution_mode == "host"


def test_host_execute_signal(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = HostEnvironment(binary)

    completed = subprocess.CompletedProcess(
        args=[],
        returncode=-11,
        stdout="",
        stderr="segfault",
    )

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: completed,
    )

    result = env.execute()

    assert result.crashed is True
    assert result.logs["signal"] == "11"


def test_host_execute_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = HostEnvironment(binary)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["bin"],
            timeout=5,
            output="partial",
            stderr="timeout",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = env.execute()

    assert result.returncode == -1
    assert result.crashed is True
    assert "Execution timeout" in result.stderr

def test_compile_missing_source():
    compiler = CCompiler(Path("/does/not/exist.c"))

    with pytest.raises(FileNotFoundError):
        compiler.compile()


def test_compile_success(monkeypatch, tmp_path):
    source = tmp_path / "test.c"
    source.write_text("int main(){return 0;}")

    compiler = CCompiler(source, tmp_path)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        ),
    )

    binary = compiler.compile()

    assert binary == tmp_path / "test.out"


def test_compile_failure(monkeypatch, tmp_path):
    source = tmp_path / "bad.c"
    source.write_text("broken")

    compiler = CCompiler(source, tmp_path)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="gcc error",
        ),
    )

    with pytest.raises(RuntimeError):
        compiler.compile()


def test_compile_with_extra_flags(monkeypatch, tmp_path):
    source = tmp_path / "test.c"
    source.write_text("int main(){return 0;}")
    compiler = CCompiler(source, tmp_path)

    captured_cmd = []

    def fake_run(cmd, **kwargs):
        captured_cmd.extend(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    compiler.compile(extra_flags=["-g", "-DDEBUG"])

    assert "-g" in captured_cmd
    assert "-DDEBUG" in captured_cmd
    assert "-O2" in captured_cmd

def test_compile_and_run(monkeypatch, tmp_path):
    src = tmp_path / "x.c"
    src.write_text("int main(){return 0;}")

    isolate = Isolate()
    fake_binary = tmp_path / "x.out"

    monkeypatch.setattr(
        CCompiler,
        "compile",
        lambda self, flags=None: fake_binary,
    )

    expected = ExecutionResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="host",
        logs={},
        duration_ms=1.0,
        crashed=False,
    )

    monkeypatch.setattr(
        Isolate,
        "run_binary",
        lambda self, path: expected,
    )

    result = isolate.compile_and_run(src)

    assert result is expected


def test_run_binary_no_env_permission_denied(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate()

    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.is_available",
        lambda self: False,
    )

    monkeypatch.setattr(
        "isolate.QEMUEnvironment.is_available",
        lambda self: False,
    )

    monkeypatch.setattr(
        isolate,  # self attr
        "_ask_user_permission",
        lambda: False,
    )

    result = isolate.run_binary(binary)

    assert result is None


def test_run_binary_host_allowed(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate()
    isolate.allow_host_execution = True
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.is_available",
        lambda self: False,
    )
    monkeypatch.setattr(
        "isolate.QEMUEnvironment.is_available",
        lambda self: False,
    )

    fake_result = ExecutionResult(
        stdout="ok", stderr="", returncode=0,
        execution_mode="host", logs={}, duration_ms=1.0, crashed=False
    )
    monkeypatch.setattr("isolate.HostEnvironment.execute", lambda self: fake_result)

    result = isolate.run_binary(binary)

    assert result is fake_result
    assert result is not None
    assert result.execution_mode == "host"


def test_ask_user_permission_yes(monkeypatch):
    monkeypatch.setattr(
        "builtins.input",
        lambda _: "yes",
    )

    assert Isolate._ask_user_permission() is True


def test_ask_user_permission_no(monkeypatch):
    monkeypatch.setattr(
        "builtins.input",
        lambda _: "n",
    )

    assert Isolate._ask_user_permission() is False

def test_qemu_execute_detects_crash(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QEMUEnvironment(binary, 10)

    monkeypatch.setattr(QEMUEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_create_initrd", lambda path: None)
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(env, "_get_kernel_cmdline", lambda: "console=ttyS0")

    qemu_stdout = """
=== BINARY OUTPUT START ===
Kernel panic
=== BINARY OUTPUT END ===
EXIT_CODE=0
"""

    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=qemu_stdout,
        stderr=""
    )

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)

    result = env.execute()

    assert result.crashed is True

def test_qemu_execute_nonzero_exit_code(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QEMUEnvironment(binary, 10)
    monkeypatch.setattr(QEMUEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_create_initrd", lambda path: None)
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(env, "_get_kernel_cmdline", lambda: "console=ttyS0")

    qemu_stdout = """
=== BINARY OUTPUT START ===
ok
=== BINARY OUTPUT END ===
EXIT_CODE=13
"""
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=qemu_stdout,
        stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)

    result = env.execute()

    assert result.stdout == "ok"
    assert result.returncode == 0
    assert result.crashed is False
    assert result.logs["exit_code"] == "13"


def test_qemu_execute_preserves_qemu_stderr(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QEMUEnvironment(binary, 10)
    monkeypatch.setattr(QEMUEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_create_initrd", lambda path: None)
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(env, "_get_kernel_cmdline", lambda: "console=ttyS0")

    qemu_stdout = """
=== BINARY OUTPUT START ===
ok
=== BINARY OUTPUT END ===
EXIT_CODE=0
"""
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=qemu_stdout,
        stderr="qemu: warning: something minor",
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: completed)

    result = env.execute()

    assert result.stdout == "ok"
    assert result.stderr == "qemu: warning: something minor"
    assert result.crashed is False
    assert result.execution_mode == "qemu"