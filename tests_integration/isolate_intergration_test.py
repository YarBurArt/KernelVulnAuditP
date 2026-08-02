from pathlib import Path

import pytest

from isolate import (
    CCompiler,
    QemuEnvironment,
)


@pytest.mark.integration
def test_real_compile_and_execute_qemu():
    source = Path("tests/isolate_synthetic_poc.c")

    assert source.exists()

    compiler = CCompiler(source)

    binary = compiler.compile()

    assert binary
    assert binary.exists()

    env = QemuEnvironment(binary, timeout=60)

    if not env.is_available():
        pytest.skip("qemu-system-x86_64 unavailable")

    result = env.execute()

    # print('\nstdout:\n', result.stdout)
    # print('\nstderr:\n', result.stderr)
    # print('\nlogs:\n', result.logs)

    assert result.execution_mode == "qemu"
    assert result.returncode == 0
    assert result.duration_ms > 0

    assert isinstance(result.kernel_info, dict)
    assert isinstance(result.resources, dict)
    assert isinstance(result.modules, list)
    assert isinstance(result.processes, list)
    assert isinstance(result.files, list)

    # audit data
    assert result.kernel_info.get("uname")
    assert result.resources.get("meminfo")
    assert result.modules
    assert result.processes
    assert result.files

    # execution
    assert result.logs["kernel_path"]
    assert result.logs["initrd_created"]
    assert result.logs["command"]
    assert result.logs["exit_code"] == "0"

    assert "Linux" in result.kernel_info["uname"]
    assert any("/proc" in f for f in result.files)

    assert "POC_OK" in result.stdout

    assert result.logs["exit_code"] == "0"


@pytest.mark.integration
def test_real_compile_and_execute_qemu_logs_integrity():
    source = Path("tests/isolate_synthetic_poc.c")
    assert source.exists()

    compiler = CCompiler(source)
    binary = compiler.compile()

    assert binary
    assert binary.exists()

    env = QemuEnvironment(binary, timeout=60)

    if not env.is_available():
        pytest.skip("qemu-system-x86_64 unavailable")

    result = env.execute()

    required_logs = {
        "stage",
        "binary",
        "timeout",
        "kernel_path",
        "initrd_created",
        "command",
        "qemu_returncode",
        "stdout_size",
        "stderr_size",
        "exit_code",
    }

    missing = required_logs - set(result.logs)

    assert not missing, f"missing logs: {missing}"

    assert int(result.logs["stdout_size"]) > 0
    assert int(result.logs["stderr_size"]) >= 0

    assert result.logs["exit_code"] == "0"
    assert result.logs["qemu_returncode"] == "0"

    assert result.kernel_info
    assert result.resources
    assert len(result.modules) > 0
    assert len(result.processes) > 0
    assert len(result.files) > 0

    assert "POC_OK" in result.stdout
