import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from core.entities import RunLogs, SandboxRunResult
from isolate import CCompiler, HostEnvironment, Isolate
from isolate.parse_vm_internal_results import QEMU_CRASH_PATTERNS, ParseVmResults
from isolate.qemu_vm import QemuEnvironment
from isolate.virtme_ng_vm import VirtmeNGEnvironment


class FakeTempDir:
    def __init__(self, path: Path):
        self.path = str(path)

    def __enter__(self):
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


def test_execution_result_to_json():
    result = SandboxRunResult(
        stdout="out",
        stderr="err",
        returncode=0,
        execution_mode="qemu",
        logs=RunLogs(binary="b"),
        duration_ms=1.5,
        crashed=False,
    )

    data = json.loads(result.to_json())

    assert data["stdout"] == "out"
    assert data["stderr"] == "err"
    assert data["returncode"] == 0
    assert data["execution_mode"] == "qemu"
    assert data["crashed"] is False
    assert data["logs"]["binary"] == "b"


def test_parse_guest_output_sections():
    parser = ParseVmResults()

    output = """========== VM START ==========
Sat Aug  1 12:00:00 UTC 2026
Linux test 6.1.0 #1 SMP
========== CMDLINE ==========
console=ttyS0
========== RESOURCES ==========
0.00 0.01 0.02 1/123 456
some stat line
========== MODULES ==========
mod1
mod2
========== FILESYSTEM SNAPSHOT ==========
drwxr-xr-x bin
========== PROCESS LIST ==========
PID USER
"""

    kernel_info, resources, modules, files, processes = parser.parse_guest_output(
        output
    )

    assert kernel_info["date"] == "Sat Aug  1 12:00:00 UTC 2026"
    assert kernel_info["uname"] == "Linux test 6.1.0 #1 SMP"
    assert kernel_info["cmdline"] == "console=ttyS0"
    assert resources["loadavg"] == "0.00 0.01 0.02 1/123 456"
    assert resources["stat"] == "some stat line"
    assert modules == ["mod1", "mod2"]
    assert files == ["drwxr-xr-x bin"]
    assert processes == ["PID USER"]


def test_parse_guest_output_no_sections():
    parser = ParseVmResults()

    kernel_info, resources, modules, files, processes = parser.parse_guest_output(
        "random noise\nno sections here"
    )

    assert kernel_info == {}
    assert resources == {}
    assert modules == []
    assert files == []
    assert processes == []


@pytest.mark.parametrize(
    "text",
    [
        "Kernel panic",
        "BUG:",
        "Oops:",
        "segfault",
        "general protection fault",
    ],
)
def test_qemu_detect_crash(text):
    assert ParseVmResults.detect_crash(text, QEMU_CRASH_PATTERNS) is True


def test_qemu_detect_crash_negative():
    assert ParseVmResults.detect_crash("hello world", QEMU_CRASH_PATTERNS) is False


def test_parse_exit_code_bad_value_keeps_previous():
    assert ParseVmResults.parse_exit_code("EXIT_CODE=notanumber\n") == 0


def test_parse_exit_code_invalid_then_valid():
    assert (
        ParseVmResults.parse_exit_code("EXIT_CODE=abc\nEXIT_CODE=7\n") == 7
    )


def test_parse_exit_code_multiple_last_wins():
    assert (
        ParseVmResults.parse_exit_code("EXIT_CODE=1\nEXIT_CODE=2\n") == 2
    )


def test_parse_guest_output_dmesg_cpu_memory_sections():
    parser = ParseVmResults()

    output = """========== VM START ==========
Sat Aug  1 12:00:00 UTC 2026
Linux test 6.1.0 #1 SMP
========== DMESG ==========
[    0.000000] Linux version 6.1.0
========== CPU ==========
processor : 0
========== MEMORY ==========
MemTotal: 512
"""

    kernel_info, resources, _modules, _files, _processes = parser.parse_guest_output(
        output
    )

    assert kernel_info["dmesg"] == "[    0.000000] Linux version 6.1.0"
    assert resources["cpuinfo"] == "processor : 0"
    assert resources["meminfo"] == "MemTotal: 512"


def test_parse_guest_output_modules_fallback_from_dmesg():
    parser = ParseVmResults()

    output = """========== DMESG ==========
[    1.0] ext4 loaded
[    2.0] kvm loaded
"""

    _kernel_info, _resources, modules, _files, _processes = parser.parse_guest_output(
        output
    )

    assert modules == ["ext4", "kvm"]


def test_parse_guest_output_resources_single_line():
    parser = ParseVmResults()

    output = """========== RESOURCES ==========
0.00 0.01 0.02 1/123 456
"""

    _kernel_info, resources, _modules, _files, _processes = parser.parse_guest_output(
        output
    )

    assert resources["loadavg"] == "0.00 0.01 0.02 1/123 456"
    assert "stat" not in resources


def test_virtme_execute_success(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = VirtmeNGEnvironment(binary, 10, memory_mb=512, cpus=1)
    monkeypatch.setattr(VirtmeNGEnvironment, "is_available", lambda self: True)

    guest_out = (
        "========== VM START ==========\n"
        "Sat Aug  1 12:00:00 UTC 2026\n"
        "Linux virtme-ng 6.1.0-virtme x86_64\n"
        "========== MODULES ==========\n"
        "mod1\n"
        "========== FILESYSTEM SNAPSHOT ==========\n"
        "drwxr-xr-x bin\n"
        "========== PROCESS LIST ==========\n"
        "PID USER\n"
        "========== BINARY OUTPUT ==========\n"
        "POC_OK\n"
        "EXIT_CODE=0\n"
    )

    def fake_run(cmd, **kwargs):
        stdout = kwargs.get("stdout")
        if stdout is not None:
            stdout.write(guest_out.encode())
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("isolate.virtme_ng_vm.run_cmd", fake_run)

    result = env.execute()

    assert result.returncode == 0
    assert result.crashed is False
    assert result.execution_mode == "virtme-ng"
    assert "POC_OK" in result.stdout
    assert result.logs.exit_code == "0"
    assert result.logs.virtme_returncode == "0"
    assert result.logs.stage == "vm_finished"
    assert result.kernel_info.uname == "Linux virtme-ng 6.1.0-virtme x86_64"
    assert result.modules == ["mod1"]
    assert result.processes == ["PID USER"]


def test_virtme_execute_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = VirtmeNGEnvironment(binary, 5)
    monkeypatch.setattr(VirtmeNGEnvironment, "is_available", lambda self: True)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["virtme-ng"], timeout=5)

    monkeypatch.setattr("isolate.virtme_ng_vm.run_cmd", fake_run)

    result = env.execute()

    assert result.returncode == -1
    assert result.crashed is True
    assert "Execution timeout" in result.stderr
    assert result.logs.error


def test_virtme_execute_raises_when_unavailable(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = VirtmeNGEnvironment(binary, 10)
    monkeypatch.setattr(VirtmeNGEnvironment, "is_available", lambda self: False)

    with pytest.raises(RuntimeError):
        env.execute()


def test_qemu_execute_success(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = QemuEnvironment(binary, 10)
    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    (tmp_path / "serial.log").write_text("noise\nEXIT_CODE=42\n")
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    monkeypatch.setattr(
        "isolate.qemu_vm.run_cmd",
        lambda *a, **k: completed,
    )

    result = env.execute()

    # the guest's EXIT_CODE is the meaningful outcome, not qemu's own rc
    assert result.returncode == 42
    assert result.stdout == "noise\nEXIT_CODE=42\n"
    assert result.crashed is False
    assert result.execution_mode == "qemu"
    assert result.logs.exit_code == "42"
    assert result.logs.stage == "vm_finished"


def test_qemu_execute_timeout(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = QemuEnvironment(binary, 5)
    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["qemu"], timeout=5, output="partial", stderr="timeout"
        )

    monkeypatch.setattr("isolate.qemu_vm.run_cmd", fake_run)

    result = env.execute()

    assert result.returncode == -1
    assert result.crashed is True
    assert "execution timeout" in result.stderr
    assert result.logs.stdout_size == "0"
    assert result.logs.stderr_size == "7"


def test_qemu_execute_timeout_no_partial_stderr(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")
    env = QemuEnvironment(binary, 5)
    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    (tmp_path / "serial.log").write_text("boot noise")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["qemu"], timeout=5)

    monkeypatch.setattr("isolate.qemu_vm.run_cmd", fake_run)

    result = env.execute()

    assert result.returncode == -1
    assert result.crashed is True
    assert result.logs.stderr_size == "0"


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
    assert result.logs.signal == "11"


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
        "isolate.isolate.run_cmd",
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
        "isolate.isolate.run_cmd",
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

    monkeypatch.setattr("isolate.isolate.run_cmd", fake_run)

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

    expected = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="host",
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
        "isolate.QemuEnvironment.is_available",
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
        "isolate.QemuEnvironment.is_available",
        lambda self: False,
    )

    fake_result = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="host",
        duration_ms=1.0,
        crashed=False,
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


def test_run_binary_backend_host(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate(backend="host")

    fake_result = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="host",
        duration_ms=1.0,
        crashed=False,
    )
    monkeypatch.setattr("isolate.HostEnvironment.execute", lambda self: fake_result)

    result = isolate.run_binary(binary)

    assert result is fake_result
    assert result.execution_mode == "host"


def test_run_binary_backend_forced_virtme(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate(backend="virtme-ng")

    fake_result = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="virtme-ng",
        duration_ms=1.0,
        crashed=False,
    )
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.is_available", lambda self: True
    )
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.execute", lambda self: fake_result
    )

    result = isolate.run_binary(binary)

    assert result is fake_result
    assert result.execution_mode == "virtme-ng"


def test_run_binary_backend_forced_qemu(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate(backend="qemu")

    fake_result = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="qemu",
        duration_ms=1.0,
        crashed=False,
    )
    monkeypatch.setattr("isolate.QemuEnvironment.is_available", lambda self: True)
    monkeypatch.setattr("isolate.QemuEnvironment.execute", lambda self: fake_result)

    result = isolate.run_binary(binary)

    assert result is fake_result
    assert result.execution_mode == "qemu"


def test_run_binary_backend_forced_missing(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate(backend="qemu")
    monkeypatch.setattr("isolate.QemuEnvironment.is_available", lambda self: False)
    monkeypatch.setattr(isolate, "_ask_user_permission", lambda: False)

    result = isolate.run_binary(binary)

    assert result is None


def test_run_binary_unknown_backend_falls_back_to_auto(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate(backend="bogus")
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.is_available", lambda self: False
    )
    monkeypatch.setattr("isolate.QemuEnvironment.is_available", lambda self: False)
    monkeypatch.setattr(isolate, "_ask_user_permission", lambda: False)

    result = isolate.run_binary(binary)

    assert result is None


def test_run_binary_auto_skips_failed_backend(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    isolate = Isolate()

    def failing_execute(self):
        raise RuntimeError("virtme-ng exploded")

    fake_qemu = SandboxRunResult(
        stdout="ok",
        stderr="",
        returncode=0,
        execution_mode="qemu",
        duration_ms=1.0,
        crashed=False,
    )
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.is_available", lambda self: True
    )
    monkeypatch.setattr(
        "isolate.VirtmeNGEnvironment.execute", failing_execute
    )
    monkeypatch.setattr("isolate.QemuEnvironment.is_available", lambda self: True)
    monkeypatch.setattr("isolate.QemuEnvironment.execute", lambda self: fake_qemu)

    result = isolate.run_binary(binary)

    assert result is fake_qemu
    assert result.execution_mode == "qemu"


def test_isolate_backend_from_config(monkeypatch):
    import isolate.isolate as iso_mod
    from isolate import Isolate as Iso

    monkeypatch.setattr(iso_mod, "SANDBOX_BACKEND", "qemu")
    assert Iso().backend == "qemu"

    monkeypatch.setattr(iso_mod, "SANDBOX_BACKEND", "virtme-ng")
    assert Iso().backend == "virtme-ng"

    monkeypatch.setattr(iso_mod, "SANDBOX_BACKEND", "bogus")
    assert Iso().backend == "auto"


def test_qemu_execute_detects_crash(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QemuEnvironment(binary, 10)

    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    (tmp_path / "serial.log").write_text("Kernel panic\nEXIT_CODE=0\n")

    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr("isolate.qemu_vm.run_cmd", lambda *a, **k: completed)

    result = env.execute()

    assert result.crashed is True


def test_qemu_execute_nonzero_exit_code(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QemuEnvironment(binary, 10)
    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    (tmp_path / "serial.log").write_text("ok\nEXIT_CODE=13\n")
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="",
    )
    monkeypatch.setattr("isolate.qemu_vm.run_cmd", lambda *a, **k: completed)

    result = env.execute()

    assert result.stdout == "ok\nEXIT_CODE=13\n"
    # the guest's EXIT_CODE is the meaningful outcome, not qemu's own rc
    assert result.returncode == 13
    assert result.crashed is False
    assert result.logs.exit_code == "13"


def test_qemu_execute_preserves_qemu_stderr(monkeypatch, tmp_path):
    binary = tmp_path / "bin"
    binary.write_text("x")

    env = QemuEnvironment(binary, 10)
    monkeypatch.setattr(QemuEnvironment, "is_available", lambda self: True)
    monkeypatch.setattr(env, "_build_initrd", lambda workdir: tmp_path / "initrd.cpio")
    monkeypatch.setattr(env, "_find_kernel", lambda: Path("/boot/vmlinuz"))
    monkeypatch.setattr(tempfile, "TemporaryDirectory", lambda: FakeTempDir(tmp_path))

    (tmp_path / "serial.log").write_text("ok\nEXIT_CODE=0\n")
    completed = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="qemu: warning: something minor",
    )
    monkeypatch.setattr("isolate.qemu_vm.run_cmd", lambda *a, **k: completed)

    result = env.execute()

    assert result.stdout == "ok\nEXIT_CODE=0\n"
    assert result.stderr == "qemu: warning: something minor"
    assert result.crashed is False
    assert result.execution_mode == "qemu"
