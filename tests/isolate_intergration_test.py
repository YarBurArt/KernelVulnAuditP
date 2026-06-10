import pytest
from pathlib import Path

from isolate import (
    CCompiler,
    QEMUEnvironment,
)


@pytest.mark.integration
def test_real_compile_and_execute_qemu():
    source = Path('tests/isolate_synthetic_poc.c')

    assert source.exists()

    compiler = CCompiler(source)

    binary = compiler.compile()

    assert binary
    assert binary.exists()

    env = QEMUEnvironment(binary, timeout=60)

    if not env.is_available():
        pytest.skip('qemu-system-x86_64 unavailable')

    result = env.execute()

    print('\nstdout:\n', result.stdout)
    print('\nstderr:\n', result.stderr)
    print('\nlogs:\n', result.logs)

    assert result.execution_mode == 'qemu'
    assert result.returncode == 0
    assert result.crashed is False
    assert result.duration_ms > 0
    assert result.logs['stage'] == 'vm_finished'

    assert result.logs['kernel_path']
    assert result.logs['initrd_created']
    assert result.logs['command']

    assert 'POC_OK' in result.stdout

    assert result.logs['exit_code'] == '0'


@pytest.mark.integration
def test_real_compile_and_execute_qemu_logs_integrity():
    source = Path('tests/isolate_synthetic_poc.c')
    assert source.exists()

    compiler = CCompiler(source)
    binary = compiler.compile()

    assert binary
    assert binary.exists()

    env = QEMUEnvironment(binary, timeout=60)

    if not env.is_available():
        pytest.skip('qemu-system-x86_64 unavailable')

    result = env.execute()

    required_logs = {
        'stage', 'binary', 'timeout', 'kernel_path', 'initrd_created', 'command',
        'qemu_returncode', 'stdout_size', 'stderr_size', 'exit_code',
    }

    missing = required_logs - set(result.logs)

    assert not missing, f'missing logs: {missing}'

    assert result.logs['stage'] == 'vm_finished'

    assert int(result.logs['stdout_size']) > 0

    assert int(result.logs['stderr_size']) >= 0

    assert result.logs['exit_code'] == '0'

    assert result.logs['qemu_returncode'] == '0'

    assert 'POC_OK' in result.stdout