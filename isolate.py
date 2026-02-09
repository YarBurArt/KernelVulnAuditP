#!/usr/bin/env python3
"""
relatively safe compile and run xpl binaries in isolated environments.
Supports virtme-ng/virtme, QEMU microvm, 
and host execution with comprehensive logging
"""
import subprocess
import tempfile
import shutil
import os
import sys
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Literal
from datetime import datetime
import re

# binary start and end markers to track stdout
BIN_INIT = '''#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== BINARY OUTPUT START ==="
{bin_path}
EXITCODE=$?
echo "=== BINARY OUTPUT END ==="
echo "EXIT_CODE=$EXITCODE"

sync
poweroff -f
'''


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int
    execution_mode: Literal['virtme-ng', 'qemu', 'host']
    logs: dict
    duration_ms: float
    crashed: bool = False
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)


class IsolationEnvironment:
    """base of isolation environments"""
    def __init__(self, binary_path: Path, timeout: int = 30):
        self.binary_path = binary_path
        self.timeout = timeout
        self.logs = {}
    
    def is_available(self) -> bool:
        raise NotImplementedError
    
    def execute(self) -> ExecutionResult:
        raise NotImplementedError
    
    def _log(self, key: str, value: str):
        self.logs[key] = value


class VirtmeNGEnvironment(IsolationEnvironment):
    """
    this is the most stable solution,
    a lightweight virtualization of current environment, but
    better read docs here https://github.com/arighi/virtme-ng
    """
    def is_available(self) -> bool:
        return shutil.which('virtme-ng') is not None
    
    def execute(self) -> ExecutionResult:
        start = datetime.now()
        cmd = [
            'virtme-ng', '--exec',
            f'{self.binary_path.absolute()}',
            '--quiet', '--memory', '512M',
        ]
        self._log('command', ' '.join(cmd))  # log stdin

        try:
            result = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=self.timeout
            )
            
            duration = (datetime.now() - start).total_seconds() * 1000
            crashed = self._detect_crash(result.stderr)
            
            self._log('virtme_version', self._get_virtme_version())
            self._log('kernel_version', self._get_kernel_version())
            
            # take stdout/err from subproc run from vng
            return ExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                execution_mode='virtme-ng',
                logs=self.logs,
                duration_ms=duration,
                crashed=crashed
            )
            
        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start).total_seconds() * 1000
            self._log('error', f'Timeout after {self.timeout}s')
            return ExecutionResult(
                stdout='',
                stderr=f'Execution timeout ({self.timeout}s)',
                returncode=-1,
                execution_mode='virtme-ng',
                logs=self.logs,
                duration_ms=duration,
                crashed=True
            )
    
    def _get_virtme_version(self) -> str:
        try:
            result = subprocess.run(
                ['virtme-ng', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except:
            return 'unknown'
    
    def _get_kernel_version(self) -> str:
        # TODO: take from db , slower but more sources
        try:
            with open('/proc/version', 'r') as f:
                return f.read().strip()
        except:
            return 'unknown'
    
    def _detect_crash(self, stderr: str) -> bool:
        crash_patterns = [r'kernel panic', r'segmentation fault',
            r'general protection fault', r'BUG:',
            r'Oops:', r'Call Trace:',
        ]
        return any(re.search(
            pattern, stderr, re.IGNORECASE
        ) for pattern in crash_patterns)


class QEMUEnvironment(IsolationEnvironment):
    """
    attempt to create a secure environment using QEMU,
    where the binary is executed immediately after vm boots up,
    https://www.qemu.org/docs/master/system/i386/microvm.html
    """
    
    def is_available(self) -> bool:
        return shutil.which('qemu-system-x86_64') is not None
    
    def execute(self) -> ExecutionResult:
        start = datetime.now()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            initrd_path = tmpdir / 'initrd.cpio'
            
            self._create_initrd(initrd_path)
            
            kernel_path = self._find_kernel()
            if not kernel_path:
                raise RuntimeError('No kernel image found')
            
            self._log('kernel_path', str(kernel_path))
            
            cmd = [
                'qemu-system-x86_64',
                '-M', 'microvm,x-option-roms=off,pit=off,pic=off,rtc=off',
                '-no-user-config',
                '-nodefaults',
                '-no-reboot',
                '-nographic',
                '-serial', 'stdio',
                '-m', '512M',
                '-kernel', str(kernel_path),
                '-initrd', str(initrd_path),
                '-append', self._get_kernel_cmdline(),
            ]
            self._log('command', ' '.join(cmd))  # log stdin
            
            try:
                result = subprocess.run(
                    cmd, capture_output=True,
                    text=True, timeout=self.timeout
                )
                
                duration = (datetime.now() - start).total_seconds() * 1000
                stdout, stderr = self._parse_qemu_output(result.stdout, result.stderr)
                crashed = self._detect_crash(stdout + stderr)
                
                return ExecutionResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=result.returncode,
                    execution_mode='qemu',
                    logs=self.logs,
                    duration_ms=duration,
                    crashed=crashed
                )
                
            except subprocess.TimeoutExpired:
                duration = (datetime.now() - start).total_seconds() * 1000
                self._log('error', f'Timeout after {self.timeout}s')
                return ExecutionResult(
                    stdout='',
                    stderr=f'Execution timeout ({self.timeout}s)',
                    returncode=-1,
                    execution_mode='qemu',
                    logs=self.logs,
                    duration_ms=duration,
                    crashed=True
                )
    
    def _create_initrd(self, output_path: Path):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            init_script = tmpdir / 'init'
            init_script.write_text(
                BIN_INIT.format(bin_path=self.binary_path.absolute())
            )
            init_script.chmod(0o755)
            
            shutil.copy(self.binary_path, tmpdir / 'binary')
            (tmpdir / 'binary').chmod(0o755)
            
            subprocess.run(
                f'cd {tmpdir} && find . | cpio -o -H newc > {output_path}',
                shell=True,
                check=True,
                capture_output=True
            )
    
    def _find_kernel(self) -> Optional[Path]:
        kernel_paths = ['/boot/vmlinuz', 
            f'/boot/vmlinuz-{os.uname().release}',
            '/boot/vmlinuz-linux',]
        for path in kernel_paths:
            p = Path(path)
            if p.exists():
                return p
        
        boot_dir = Path('/boot')
        if boot_dir.exists():
            vmlinuz_files = sorted(boot_dir.glob('vmlinuz-*'), reverse=True)
            if vmlinuz_files:
                return vmlinuz_files[0]
    
    def _get_kernel_cmdline(self) -> str:
        base_params = ['console=ttyS0', 'quiet', 
            'loglevel=3', 'panic=-1', 'init=/init',]
        try:
            with open('/proc/cmdline', 'r') as f:
                host_params = f.read().strip().split()
                relevant_params = [p for p in host_params if any(
                    p.startswith(prefix) for prefix in ['root=', 'rootfstype=', 'ro', 'rw']
                )]
                base_params.extend(relevant_params)
        except:  # FIXME
            pass
        
        return ' '.join(base_params)
    
    def _parse_qemu_output(self, stdout: str, stderr: str) -> tuple[str, str]:
        lines = stdout.split('\n')
        
        in_output = False
        output_lines = []
        exit_code = 0
        
        for line in lines:
            if '=== BINARY OUTPUT START ===' in line:
                in_output = True
                continue
            elif '=== BINARY OUTPUT END ===' in line:
                in_output = False
                continue
            elif line.startswith('EXIT_CODE='):
                try:
                    exit_code = int(line.split('=')[1])
                except:
                    pass
                continue
            
            if in_output:
                output_lines.append(line)
        
        self._log('exit_code', str(exit_code))
        return '\n'.join(output_lines), stderr
    
    def _detect_crash(self, output: str) -> bool:
        crash_patterns = [
            r'kernel panic', r'segmentation fault',
            r'general protection fault',
            r'BUG:', r'Oops:', r'RIP:',
        ]
        return any(re.search(
            pattern, output, re.IGNORECASE
        ) for pattern in crash_patterns)


class HostEnvironment(IsolationEnvironment):
    """
    try direct execution like in prototype, 
    on host with extended logging, docs whats need: 
    https://docs.python.org/3/library/subprocess.html#using-the-subprocess-module
    """
    
    def is_available(self) -> bool:
        return True  # TODO: check from user cfg
    
    def execute(self) -> ExecutionResult:
        start = datetime.now()
        
        self._log('warning', 'Executing on host system - take that risk! :)')
        self._log('binary_path', str(self.binary_path.absolute()))
        self._log('binary_permissions', oct(self.binary_path.stat().st_mode))
        self._log('working_directory', os.getcwd())
        self._log('user', os.getenv('USER', 'unknown'))
        
        env = os.environ.copy()
        env['LD_PRELOAD'] = ''
        
        cmd = [str(self.binary_path.absolute())]
        self._log('command', ' '.join(cmd))  # log stdin
        
        try:
            result = subprocess.run(
                cmd, capture_output=True,
                text=True, timeout=self.timeout,
                env=env, cwd=tempfile.gettempdir()
            )
            duration = (datetime.now() - start).total_seconds() * 1000
            crashed = result.returncode < 0
            
            if crashed:
                self._log('signal', str(-result.returncode))
            
            return ExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                execution_mode='host',
                logs=self.logs,
                duration_ms=duration,
                crashed=crashed
            )
            
        except subprocess.TimeoutExpired:
            # its not mean system is not vulnerable, just xpl not run 
            duration = (datetime.now() - start).total_seconds() * 1000
            self._log('error', f'Timeout after {self.timeout}s')
            return ExecutionResult(
                stdout='',
                stderr=f'Execution timeout ({self.timeout}s)',
                returncode=-1,
                execution_mode='host',
                logs=self.logs,
                duration_ms=duration,
                crashed=True
            )


class CCompiler:
    """ abstraction layer over the compiler 
    to further add support for multiple compilers """
    
    def __init__(self, source_path: Path, output_dir: Optional[Path] = None):
        self.source_path = source_path
        self.output_dir = output_dir or Path(tempfile.gettempdir())
        self.binary_path = None
    
    def compile(self, extra_flags: list[str] = None) -> Path:
        if not self.source_path.exists():
            raise FileNotFoundError(f'Source file not found: {self.source_path}')
        self.binary_path = self.output_dir / f'{self.source_path.stem}.out'
        
        flags = ['-O2', '-Wall', '-Wextra']
        if extra_flags:
            flags.extend(extra_flags)
        
        cmd = ['gcc'] + flags + ['-o', str(self.binary_path), str(self.source_path)]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f'Compilation failed:\n{result.stderr}')
        
        return self.binary_path


class Isolate:
    """
    orchestrator for safe binary execution,
    check environment, compile 
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.allow_host_execution = False
    
    def compile_and_run(
        self,
        source_path: Path,
        compile_flags: Optional[list[str]] = None
    ) -> ExecutionResult:
        compiler = CCompiler(source_path)
        binary_path = compiler.compile(compile_flags)
        
        return self.run_binary(binary_path)
    
    def run_binary(self, binary_path: Path) -> ExecutionResult:
        environments = [
            VirtmeNGEnvironment(binary_path, self.timeout),
            QEMUEnvironment(binary_path, self.timeout),
        ]
        
        for env in environments:
            if env.is_available():
                print(f'Using {env.__class__.__name__}', file=sys.stderr)
                return env.execute()
        
        if not self.allow_host_execution:
            if not self._ask_user_permission():
                print('No virtualization available and host execution denied')
                return  # FIXME
        
        print('Executing on host system', file=sys.stderr)
        host_env = HostEnvironment(binary_path, self.timeout)
        return host_env.execute()
    
    def _ask_user_permission(self) -> bool:
        # TODO: Flet support
        print('\n' + '=' * 60 + '\n'
              'WARNING: No virtualization environment available\n'
              'virtme-ng: not found\n'
              'qemu-system-x86_64: not found\n'
              + '=' * 60 + '\n'
              'The binary can only be executed directly on the host.\n'
              'This may be a bit DANGEROUS if the binary crashes the kernel :)\n'
              '\nAllow host execution? [y/N]: ', file=sys.stderr, end='')
        try:
            response = input().strip().lower()
            return response in ['y', 'yes']
        except (EOFError, KeyboardInterrupt):
            print('\nAborted.', file=sys.stderr)
            return False


def main():
    """ only for testing """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='test mode for binary isolation'
    )
    parser.add_argument(
        'source', type=Path, help='C source file to compile and run')
    parser.add_argument(
        '--timeout', type=int, default=30, help='Execution timeout in seconds')
    parser.add_argument(
        '--compile-flags', nargs='*', help='Additional GCC flags')
    parser.add_argument(
        '--allow-host', action='store_true', help='Allow host execution without prompt')
    parser.add_argument(
        '--json', action='store_true', help='Output results as JSON')
    args = parser.parse_args()
    
    isolate = Isolate(timeout=args.timeout)
    isolate.allow_host_execution = args.allow_host
    
    try:
        result = isolate.compile_and_run(args.source, args.compile_flags)
        
        if args.json:
            print(result.to_json())
        else:
            print(f'\n=== Execution Mode: {result.execution_mode} ===\n'
                  f'Duration: {result.duration_ms:.2f}ms\n'
                  f'Return Code: {result.returncode}\n'
                  f'Crashed: {result.crashed}')
                        
            if result.logs:
                print('\n=== Logs ===')
                for key, value in result.logs.items():
                    print(f'{key}: {value}')
            print('\n=== STDOUT ===\n',result.stdout)
            if result.stderr:
                print('\n=== STDERR ===\n', result.stderr)
        sys.exit(result.returncode)
        
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
