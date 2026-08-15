#!/usr/bin/env python3
"""
relatively safe compile and run xpl binaries in isolated environments.
Supports virtme-ng/virtme, QEMU microvm,
and host execution with comprehensive logging
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from config import ALLOW_HOST_EXECUTION, SANDBOX_BACKEND

logger = logging.getLogger(f"kernel_audit.{__name__}")
# the assets live at the repo root, not inside the isolate/ package
ASSETS = Path(__file__).resolve().parent.parent / "assets"

# binary start and end markers to track stdout
BIN_INIT = """#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo "=== INIT STARTED ==="
ls -la /
echo "=== BEFORE BINARY ==="

echo "=== VM INFO START ==="

uname -a
cat /proc/version
cat /proc/cmdline

id

lsmod

cat /proc/modules

sysctl -a 2>/dev/null

echo "=== VM INFO END ==="

echo "=== BINARY OUTPUT START ==="
{bin_path}
EXITCODE=$?
echo "=== BINARY OUTPUT END ==="
echo "=== AFTER BINARY ==="
echo "EXIT_CODE=$EXITCODE"

sync
echo b > /proc/sysrq-trigger
"""


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    returncode: int
    execution_mode: Literal["virtme-ng", "qemu", "host"]
    duration_ms: float
    crashed: bool = False

    logs: dict[str, str] = field(default_factory=dict)

    kernel_info: dict[str, str] = field(default_factory=dict)
    resources: dict[str, str] = field(default_factory=dict)
    modules: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=4)


class IsolationEnvironment:
    """base of isolation environments"""

    def __init__(self, binary_path: Path, timeout: int = 30):
        self.binary_path = binary_path
        self.timeout = timeout
        self.logs: dict[str, str] = {}

    def is_available(self) -> bool:
        raise NotImplementedError

    def execute(self) -> ExecutionResult:
        raise NotImplementedError

    def _log(self, key: str, value: str):
        self.logs[key] = value
        logger.debug("internal log %s: %s", key, value)


class HostEnvironment(IsolationEnvironment):
    """
    try direct execution like in prototype,
    on host with extended logging, docs what's need:
    https://docs.python.org/3/library/subprocess.html#using-the-subprocess-module
    """

    def is_available(self) -> bool:
        return ALLOW_HOST_EXECUTION  # TODO: also check env from local recon

    def execute(self) -> ExecutionResult:
        start = datetime.now()

        self._log("warning", "Executing on host system - take that risk! :)")
        self._log("binary_path", str(self.binary_path.absolute()))
        self._log("binary_permissions", oct(self.binary_path.stat().st_mode))
        self._log("working_directory", os.getcwd())
        self._log("user", os.getenv("USER", "unknown"))

        env = os.environ.copy()
        env["LD_PRELOAD"] = ""

        cmd = [str(self.binary_path.absolute())]
        self._log("command", " ".join(cmd))  # log stdin

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                cwd=tempfile.gettempdir(),
            )
            duration = (datetime.now() - start).total_seconds() * 1000
            crashed = result.returncode < 0

            if crashed:
                self._log("signal", str(-result.returncode))

            return ExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                execution_mode="host",
                logs=self.logs,
                duration_ms=duration,
                crashed=crashed,
            )

        except subprocess.TimeoutExpired as e:
            # its not mean system is not vulnerable, just xpl not run
            duration = (datetime.now() - start).total_seconds() * 1000
            stdout = e.stdout or ""
            stderr = e.stderr or ""

            self._log("timeout_stdout_size", str(len(stdout)))
            self._log("timeout_stderr_size", str(len(stderr)))
            self._log("error", f"Timeout after {self.timeout}s")
            return ExecutionResult(
                stdout=stdout,
                stderr=f"Execution timeout ({self.timeout}s)\n{stderr}",
                returncode=-1,
                execution_mode="host",
                logs=self.logs,
                duration_ms=duration,
                crashed=True,
            )


class CCompiler:
    """abstraction layer over the compiler
    to further add support for multiple compilers"""

    def __init__(self, source_path: Path, output_dir: Path | None = None):
        self.source_path = source_path
        self.output_dir = output_dir or Path(tempfile.gettempdir())
        self.binary_path: Path | None = None

    def compile(self, extra_flags: list[str] | None = None) -> Path | None:
        if not self.source_path.exists():
            logger.warning("Source path %s does not exist", self.source_path)
            raise FileNotFoundError(f"Source file not found: {self.source_path}")
        self.binary_path = self.output_dir / f"{self.source_path.stem}.out"

        flags = ["-static", "-O2", "-Wall", "-Wextra"]  # static for microvm
        if extra_flags:
            logger.debug("Extra flags: %s", extra_flags)
            flags.extend(extra_flags)

        cmd = ["gcc"] + flags + ["-o", str(self.binary_path), str(self.source_path)]
        logger.debug("Compiling: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.warning("Compilation failed with exit code %d", result.returncode)
            raise RuntimeError(f"Compilation failed:\n{result.stderr}")

        return self.binary_path


class Isolate:
    """
    orchestrator for safe binary execution,
    check environment, compile
    """

    # allowed SANDBOX_BACKEND values, empty string means "auto"
    _BACKENDS: tuple[str] = {"", "auto", "virtme-ng", "qemu", "host"}

    def __init__(self, timeout: int = 120, backend: str | None = None):
        self.timeout = timeout
        self.allow_host_execution = False
        raw = (backend or SANDBOX_BACKEND).strip().lower()
        if raw not in self._BACKENDS:
            logger.warning(
                "Unknown sandbox backend %r, falling back to 'auto'", raw
            )
            raw = "auto"
        self.backend = raw or "auto"

    def compile_and_run(
        self, source_path: Path, compile_flags: list[str] | None = None
    ) -> ExecutionResult | None:
        compiler = CCompiler(source_path)
        binary_path: Path | None = compiler.compile(compile_flags)
        logger.info("Compiling completed: %s", source_path)

        if binary_path:
            return self.run_binary(binary_path)

        logger.warning("Binary path %s does not exist", binary_path)
        return None

    def run_binary(self, binary_path: Path) -> ExecutionResult | None:
        """Pick a sandbox backend from config.SANDBOX_BACKEND and run the binary"""
        from isolate.qemu_vm import QemuEnvironment
        from isolate.virtme_ng_vm import VirtmeNGEnvironment

        candidates: list[IsolationEnvironment] = []
        if self.backend in ("auto", "virtme-ng"):
            candidates.append(VirtmeNGEnvironment(binary_path, self.timeout))
        if self.backend in ("auto", "qemu"):
            candidates.append(QemuEnvironment(binary_path, self.timeout))

        failures: list[str] = []
        for env in candidates:
            try:
                if not env.is_available():
                    raise RuntimeError(
                        f"{type(env).__name__} dependencies are missing"
                    )
                logger.info("Using %s sandbox", type(env).__name__)
                return env.execute()
            except Exception as exc:
                logger.warning(
                    "%s sandbox failed: %s", type(env).__name__, exc
                )
                failures.append(f"{type(env).__name__}: {exc}")

        if (
            self.backend == "host"
            or self.allow_host_execution
            or self._ask_user_permission()
        ):
            logger.info("Executing on host system, this will be fun!")
            host_env = HostEnvironment(binary_path, self.timeout)
            return host_env.execute()

        logger.error(
            "No sandbox available%s and host execution denied",
            f" ({'; '.join(failures)})" if failures else "",
        )
        return None

    @staticmethod
    def _ask_user_permission() -> bool:
        # TODO: alert support
        logger.warning(
            "\n" + "=" * 60 + "\n"
            "No virtualization environment available\n"
            "virtme-ng: not found\n"
            "qemu-system-x86_64: not found\n" + "=" * 60 + "\n"
            "The binary can only be executed directly on the host.\n"
            "This may be a bit DANGEROUS if "
            "the binary crashes the kernel :)\n"
        )
        try:
            response = input("Allow host execution? [y/N]: ").strip().lower()
            return response in ["y", "yes"]
        except EOFError, KeyboardInterrupt:
            logger.info("\nAborted.")
            return False
