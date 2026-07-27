#!/usr/bin/env python3
"""
relatively safe compile and run xpl binaries in isolated environments.
Supports virtme-ng/virtme, QEMU microvm,
and host execution with comprehensive logging
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, Optional

from config import ALLOW_HOST_EXECUTION

logger = logging.getLogger(f"kernel_audit.{__name__}")
ASSETS = Path(__file__).parent / "assets"

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


class VirtmeNGEnvironment(IsolationEnvironment):
    """
    this is the most stable solution,
    a lightweight virtualization of current environment, but
    better read docs here https://github.com/arighi/virtme-ng
    """

    def is_available(self) -> bool:
        return shutil.which("virtme-ng") is not None

    def execute(self) -> ExecutionResult:
        start = datetime.now()
        cmd = [
            "virtme-ng",
            "--exec",
            f"{self.binary_path.absolute()}",
            "--quiet",
            "--memory",
            "512M",
        ]
        self._log("command", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                cwd="./cache_kernel",
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            duration = (datetime.now() - start).total_seconds() * 1000
            crashed = self._detect_crash(result.stderr)

            self._log("virtme_version", self._get_virtme_version())
            self._log("kernel_version", self._get_kernel_version())

            # take stdout/err from subproc run from vng
            return ExecutionResult(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                execution_mode="virtme-ng",
                logs=self.logs,
                duration_ms=duration,
                crashed=crashed,
            )

        except subprocess.TimeoutExpired as e:
            duration = (datetime.now() - start).total_seconds() * 1000
            stdout = str(e.stdout) or ""
            stderr = str(e.stderr) or ""

            self._log("timeout_stdout_size", str(len(stdout)))
            self._log("timeout_stderr_size", str(len(stderr)))
            self._log("error", f"Timeout after {self.timeout}s")
            return ExecutionResult(
                stdout=stdout,
                stderr=f"Execution timeout ({self.timeout}s)\n{stderr}",
                returncode=-1,
                execution_mode="virtme-ng",
                logs=self.logs,
                duration_ms=duration,
                crashed=True,
            )

    @staticmethod
    def _get_virtme_version() -> str:
        try:
            result = subprocess.run(
                ["virtme-ng", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip()
        except Exception as e:
            logger.debug("virtme-ng version not found cuz %s", e)
            return "unknown"

    @staticmethod
    def _get_kernel_version() -> str:
        # TODO: take from db , slower but more sources
        try:
            with open("/proc/version", "r") as f:
                return f.read().strip()
        except Exception as e:
            logger.debug("kernel version not found cuz %s", e)
            return "unknown"

    @staticmethod
    def _detect_crash(stderr: str) -> bool:
        crash_patterns = [
            r"kernel panic",
            r"segmentation fault",
            r"general protection fault",
            r"BUG:",
            r"Oops:",
            r"Call Trace:",
        ]
        return any(
            re.search(pattern, stderr, re.IGNORECASE) for pattern in crash_patterns
        )


class QemuEnvironment(IsolationEnvironment):
    def __init__(
        self, binary_path: Path, timeout: int = 30, memory_mb: int = 512, cpus: int = 1
    ):
        super().__init__(binary_path, timeout)
        self.memory_mb = memory_mb
        self.cpus = cpus
        self.assets = Path(__file__).parent / "assets"

    def is_available(self) -> bool:
        return all(
            [
                shutil.which("qemu-system-x86_64") is not None,
                shutil.which("cpio") is not None,
                shutil.which("musl-gcc") is not None,
                shutil.which("busybox") is not None,
            ]
        )

    def execute(self) -> ExecutionResult:
        start = time.perf_counter()
        self._log("stage", "qemu_execute_start")
        self._log("binary", str(self.binary_path))
        self._log("timeout", str(self.timeout))

        if not self.is_available():
            raise RuntimeError("qemu dependencies missing")

        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            initrd = self._build_initrd(workdir)
            self._log("initrd_created", str(initrd))

            kernel = self._find_kernel()
            self._log("kernel_path", str(kernel))
            self._log("stage", "kernel_found")
            serial_log = workdir / "serial.log"
            # a headless VM -nodefaults, -nographic with fixed resources -m, -smp ;
            # it halts on crashes -no-reboot, panic=-1 oops=panic and pipes verbose serial logs
            # to a file -serial, console=ttyS0, loglevel=7 for parsing, plus virtio-rng-pci for entropy
            cmd = [
                "qemu-system-x86_64",
                "-nodefaults",
                "-nographic",
                "-m",
                str(self.memory_mb),
                "-smp",
                str(self.cpus),
                "-kernel",
                str(kernel),
                "-initrd",
                str(initrd),
                "-append",
                "console=ttyS0 panic=-1 oops=panic loglevel=7",
                "-serial",
                f"file:{serial_log}",
                "-no-reboot",
                "-device",
                "virtio-rng-pci",
            ]
            self._log("command", " ".join(cmd))
            self._log("kernel", str(kernel))
            self._log("initrd", str(initrd))
            self._log("stage", "vm_created")

            try:
                proc = subprocess.run(
                    cmd, timeout=self.timeout, text=True, capture_output=True
                )
                self._log("stage", "vm_finished")
                self._log("qemu_returncode", str(proc.returncode))

                stdout = (
                    serial_log.read_text(errors="replace")
                    if serial_log.exists()
                    else ""
                )
                self._log("stdout_size", str(len(stdout)))
                self._log("stderr_size", str(len(proc.stderr)))

                exit_code = 0
                for line in stdout.splitlines():
                    if line.startswith("EXIT_CODE="):
                        try:
                            exit_code = int(line.removeprefix("EXIT_CODE="))
                        except ValueError:
                            pass
                self._log("exit_code", str(exit_code))

                kernel_info, resources, modules, files, processes = (
                    self._parse_guest_output(stdout)
                )
                duration = (time.perf_counter() - start) * 1000
                crashed = self._detect_crash(stdout + proc.stderr)
                return ExecutionResult(
                    stdout=stdout,
                    stderr=proc.stderr,
                    returncode=proc.returncode,
                    execution_mode="qemu",
                    duration_ms=duration,
                    crashed=crashed,
                    logs=self.logs,
                    kernel_info=kernel_info,
                    resources=resources,
                    modules=modules,
                    files=files,
                    processes=processes,
                )
            except subprocess.TimeoutExpired as e:
                duration = (time.perf_counter() - start) * 1000
                stdout = (
                    serial_log.read_text(errors="replace")
                    if serial_log.exists()
                    else ""
                )
                self._log("stdout_size", str(len(stdout)))
                self._log("stderr_size", str(len(e.stderr) if e.stderr else 0))
                return ExecutionResult(
                    stdout=stdout,
                    stderr="execution timeout",
                    returncode=-1,
                    execution_mode="qemu",
                    duration_ms=duration,
                    crashed=True,
                    logs=self.logs,
                )

    def _build_initrd(self, workdir: Path) -> Path:
        """assembles a minimal rootfs with Busybox parts and the target binary of PoC,
        then packs into a cpio archive in tmp-like dir to early boot"""
        root = workdir / "rootfs"
        root.mkdir(parents=True, exist_ok=True)

        for d in ["bin", "sbin", "proc", "sys", "dev", "tmp", "etc"]:
            (root / d).mkdir(parents=True, exist_ok=True)

        self._install_busybox(root)

        self._write_asset("audit.sh", root / "audit.sh", mode=0o755)
        self._write_guest_init(root)
        self._write_guest_script(root)
        shutil.copy2(self.binary_path, root / self.binary_path.name)
        (root / self.binary_path.name).chmod(0o755)

        archive = workdir / "initrd.cpio"

        subprocess.run(
            f'cd "{root}" && find . -print0 | cpio --null -ov --format=newc > "{archive}"',
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
        )

        self._log_initrd(archive)
        return archive

    def _write_guest_init(self, root: Path) -> None:
        code = self._load_asset("init.c")
        (root / "init.c").write_text(code)

        out = root / "init"
        subprocess.run(
            ["musl-gcc", "-static", "-Os", "-s", "-o", str(out), str(root / "init.c")],
            check=True,
        )

        (root / "init.c").unlink()

    def _write_guest_script(self, root: Path) -> None:
        script = self._load_asset("guest_script.sh").replace(
            "__POC_NAME__", self.binary_path.name
        )
        (root / "audit.sh").write_text(script)
        (root / "audit.sh").chmod(0o755)

    def _write_asset(self, name: str, dst: Path, mode: int = 0o644) -> None:
        dst.write_text(self._load_asset(name))
        dst.chmod(mode)

    def _load_asset(self, name: str) -> str:
        path = self.assets / name
        return path.read_text()

    def _log_initrd(self, archive: Path) -> None:
        with archive.open("rb") as f:
            listing = subprocess.run(
                ["cpio", "-it"],
                stdin=f,
                text=True,
                capture_output=True,
                check=True,
            )

        self._log("initrd_contents", listing.stdout)
        self._log("initrd_size", str(archive.stat().st_size))

    @staticmethod
    def _find_kernel() -> Path:
        release = os.uname().release
        candidates = [
            Path("/boot/vmlinuz"),
            Path(f"/boot/vmlinuz-{release}"),
            Path("/boot/vmlinuz-linux"),
        ]

        for c in candidates:
            if c.exists():
                return c

        raise RuntimeError("kernel not found")

    @staticmethod
    def _detect_crash(output: str) -> bool:
        patterns = [
            r"kernel panic",
            r"Oops:",
            r"BUG:",
            r"segfault",
            r"general protection fault",
        ]
        return any(re.search(p, output, re.IGNORECASE) for p in patterns)

    @staticmethod
    def _install_busybox(root: Path) -> None:
        busybox = shutil.which("busybox")
        if not busybox:
            raise RuntimeError("busybox not found")

        bin_dir = root / "bin"
        bin_dir.mkdir(exist_ok=True)

        # the necessary minimum for info about the environment inside
        shutil.copy2(busybox, bin_dir / "busybox")
        for name in [
            "sh",
            "mount",
            "cat",
            "ps",
            "ls",
            "echo",
            "find",
            "date",
            "uname",
            "dmesg",
            "sync",
            "poweroff",
            "sort",
            "lsmod",
        ]:
            (bin_dir / name).symlink_to("busybox")

    def _parse_guest_output(
        self, output: str
    ) -> tuple[
        dict[str, str],
        dict[str, str],
        list[str],
        list[str],
        list[str],
    ]:
        sections: dict[str, list[str]] = {}
        current: str | None = None

        for line in output.splitlines():
            line = line.rstrip()

            if line.startswith("==========") and line.endswith("=========="):
                current = line.strip("= ").lower().replace(" ", "_")
                assert current is not None
                sections[current] = []
                continue

            if current is not None:
                sections[current].append(line)

        kernel_info = {}
        resources = {}
        modules = []
        files = []
        processes = []

        try:
            uname = sections.get("vm_start", [])
            if len(uname) >= 2:
                kernel_info["date"] = uname[0]
                kernel_info["uname"] = uname[1]
        except Exception as e:
            self._log("parse_vm_start_error", str(e))

        try:
            cmdline = sections.get("cmdline", [])
            if cmdline:
                kernel_info["cmdline"] = "\n".join(cmdline)
        except Exception as e:
            self._log("parse_cmdline_error", str(e))

        try:
            dmesg = sections.get("dmesg", [])
            if dmesg:
                kernel_info["dmesg"] = "\n".join(dmesg)
        except Exception as e:
            self._log("parse_dmesg_error", str(e))

        try:
            cpu = sections.get("cpu", [])
            if cpu:
                resources["cpuinfo"] = "\n".join(cpu)
        except Exception as e:
            self._log("parse_cpu_error", str(e))

        try:
            mem = sections.get("memory", [])
            if mem:
                resources["meminfo"] = "\n".join(mem)
        except Exception as e:
            self._log("parse_mem_error", str(e))

        try:
            res = sections.get("resources", [])
            if len(res) >= 1:
                resources["loadavg"] = res[0]
            if len(res) >= 2:
                resources["stat"] = "\n".join(res[1:])
        except Exception as e:
            self._log("parse_resources_error", str(e))

        try:
            modules = [line for line in sections.get("modules", []) if line.strip()]
            if not modules:
                dmesg = sections.get("dmesg", [])
                import re

                for line in dmesg:
                    match = re.search(r"] ([a-zA-Z0-9_]+) loaded", line)
                    if match:
                        modules.append(match.group(1))
        except Exception as e:
            self._log("parse_modules_error", str(e))

        try:
            files = [
                line for line in sections.get("filesystem_snapshot", []) if line.strip()
            ]
        except Exception as e:
            self._log("parse_files_error", str(e))

        try:
            processes = [
                line for line in sections.get("process_list", []) if line.strip()
            ]
        except Exception as e:
            self._log("parse_processes_error", str(e))

        return kernel_info, resources, modules, files, processes


class QEMUEnvironmentMicrovm(IsolationEnvironment):
    """
    attempt to create a secure environment using QEMU,
    where the binary is executed immediately after vm boots up,
    https://www.qemu.org/docs/master/system/i386/microvm.html
    """

    def is_available(self) -> bool:
        return shutil.which("qemu-system-x86_64") is not None

    def execute(self) -> ExecutionResult:
        start = datetime.now()
        self._log("stage", "qemu_execute_start")
        self._log("binary", str(self.binary_path))
        self._log("timeout", str(self.timeout))

        with tempfile.TemporaryDirectory() as tmpdir_s:
            tmpdir = Path(tmpdir_s)
            initrd_path = tmpdir / "initrd.cpio"

            self._create_initrd(initrd_path)
            self._log("initrd_created", str(initrd_path))
            kernel_path = self._find_kernel()
            if not kernel_path:
                logger.warning("No kernel found for %s", self.binary_path)
                raise RuntimeError("No kernel image found")

            self._log("kernel_path", str(kernel_path))
            self._log("stage", "kernel_found")
            cmd = [
                "qemu-system-x86_64",
                "-M",
                "microvm,x-option-roms=off,pit=off,pic=off,rtc=off",
                "-no-user-config",
                "-nodefaults",
                "-no-reboot",
                "-nographic",
                "-serial",
                "stdio",
                "-m",
                "512M",
                "-kernel",
                str(kernel_path),
                "-initrd",
                str(initrd_path),
                "-append",
                self._get_kernel_cmdline(),
            ]
            if Path("/dev/kvm").exists():  # debug TCG
                cmd.extend(["-enable-kvm", "-cpu", "host"])
            self._log("command", " ".join(cmd))  # log stdin
            self._log("stage", "vm_created")
            logger.info("VM CREATION STARTED for %s", self.binary_path)
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout
                )
                self._log("stage", "vm_finished")
                self._log("qemu_returncode", str(result.returncode))
                self._log("stdout_size", str(len(result.stdout)))
                self._log("stderr_size", str(len(result.stderr)))
                logger.debug("Qemu microvm completed, stdout %s", result.stdout)
                duration = (datetime.now() - start).total_seconds() * 1000
                stdout, stderr = self._parse_qemu_output(result.stdout, result.stderr)
                crashed = self._detect_crash(stdout + stderr)

                return ExecutionResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=result.returncode,
                    execution_mode="qemu",
                    logs=self.logs,
                    duration_ms=duration,
                    crashed=crashed,
                )

            except subprocess.TimeoutExpired as e:
                duration = (datetime.now() - start).total_seconds() * 1000
                stdout = str(e.stdout) or ""
                stderr = str(e.stderr) or ""

                self._log("timeout_stdout_size", str(len(stdout)))
                self._log("timeout_stderr_size", str(len(stderr)))
                self._log("error", f"Timeout after {self.timeout}s")
                return ExecutionResult(
                    stdout=stdout,
                    stderr=f"Execution timeout ({self.timeout}s)\n{stderr}",
                    returncode=-1,
                    execution_mode="qemu",
                    logs=self.logs,
                    duration_ms=duration,
                    crashed=True,
                )

    def _check_initrd(self, output_path: Path):
        # log and check format details
        with output_path.open("rb") as f:
            listing = subprocess.run(
                ["cpio", "-it"],
                stdin=f,
                capture_output=True,
                text=True,
                check=True,
            )
        self._log("initrd_contents", listing.stdout)
        self._log("initrd_size", str(output_path.stat().st_size))
        contents = {
            p.removeprefix("./").rstrip("/") for p in listing.stdout.splitlines()
        }
        if "init" not in contents:
            raise RuntimeError("/init missing from initrd")
        if "binary" not in contents:
            raise RuntimeError("/binary missing from initrd")

    def _create_initrd(self, output_path: Path):
        with tempfile.TemporaryDirectory() as tmpdir_s:
            tmpdir = Path(tmpdir_s)

            init_data: str = BIN_INIT.format(bin_path="/binary")
            logger.debug(
                "Local script path is: %s, binary path in /binary",
                self.binary_path.absolute(),
            )
            init_script = tmpdir / "init"
            init_script.write_text(init_data)
            init_script.chmod(0o755)
            logger.debug("BIN_INIT: %s", init_data)

            shutil.copy(self.binary_path, tmpdir / "binary")
            (tmpdir / "binary").chmod(0o755)
            logger.info("Copied binary for initrd: %s", tmpdir / "binary")

            logger.debug(
                "Creating initrd file for %s, path %s", self.binary_path, init_script
            )
            subprocess.run(
                f"cd {tmpdir} && find . | cpio -o -H newc > {output_path}",
                shell=True,
                check=True,
                capture_output=True,
            )
            self._check_initrd(output_path)

    @staticmethod
    def _find_kernel() -> Optional[Path]:
        kernel_paths = [
            "/boot/vmlinuz",
            f"/boot/vmlinuz-{os.uname().release}",
            "/boot/vmlinuz-linux",
        ]
        for path in kernel_paths:
            p = Path(path)
            if p.exists():
                logger.debug("Found kernel %s", p)
                return p

        boot_dir = Path("/boot")
        if boot_dir.exists():
            vmlinuz_files = sorted(boot_dir.glob("vmlinuz-*"), reverse=True)
            if vmlinuz_files:
                logger.debug("Found %d vmlinuz files", len(vmlinuz_files))
                return vmlinuz_files[0]

        logger.warning("No kernel found in %s", kernel_paths)
        return None

    @staticmethod
    def _get_kernel_cmdline() -> str:
        # DEBUG ONLY
        return "console=ttyS0 init=/init panic=-1 reboot=t"

    @staticmethod
    def _get_kernel_cmdline_full() -> str:
        base_params = [
            "console=ttyS0",
            "quiet",
            "loglevel=3",
            "panic=-1",
            "init=/init",
        ]
        try:
            with open("/proc/cmdline", "r") as f:
                host_params = f.read().strip().split()
                relevant_params = [
                    p
                    for p in host_params
                    if any(
                        p.startswith(prefix)
                        for prefix in ["root=", "rootfstype=", "ro", "rw"]
                    )
                ]
                logger.debug("Found host cmd krnl params: %d", len(relevant_params))
                base_params.extend(relevant_params)
        except Exception as e:  # FIXME
            logger.warning("Failed to get kernel cmdline: %s", e)

        logger.debug("Using default cmdline: %s", base_params)
        return " ".join(base_params)

    def _parse_qemu_output(self, stdout: str, stderr: str) -> tuple[str, str]:
        lines = stdout.split("\n")

        in_output = False
        output_lines = []
        exit_code = 0

        for line in lines:
            if "=== BINARY OUTPUT START ===" in line:
                in_output = True
                continue
            if "=== BINARY OUTPUT END ===" in line:
                in_output = False
                continue
            if line.startswith("EXIT_CODE="):
                try:
                    exit_code = int(line.split("=")[1])
                except Exception as e:
                    logger.debug("mistake parse exit_code: %s", e)
                    pass
                continue

            if in_output:
                output_lines.append(line)

        self._log("exit_code", str(exit_code))
        return "\n".join(output_lines), stderr

    @staticmethod
    def _detect_crash(output: str) -> bool:
        crash_patterns = [
            r"kernel panic",
            r"segmentation fault",
            r"general protection fault",
            r"BUG:",
            r"Oops:",
            r"RIP:",
        ]
        return any(
            re.search(pattern, output, re.IGNORECASE) for pattern in crash_patterns
        )


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
            stdout = str(e.stdout) or ""
            stderr = str(e.stderr) or ""

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

    def __init__(self, source_path: Path, output_dir: Optional[Path] = None):
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

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.allow_host_execution = False

    def compile_and_run(
        self, source_path: Path, compile_flags: Optional[list[str]] = None
    ) -> ExecutionResult | None:
        compiler = CCompiler(source_path)
        binary_path: Path | None = compiler.compile(compile_flags)
        logger.info("Compiling completed: %s", source_path)

        if binary_path:
            return self.run_binary(binary_path)

        logger.warning("Binary path %s does not exist", binary_path)
        return None

    def run_binary(self, binary_path: Path) -> ExecutionResult | None:
        environments = [
            VirtmeNGEnvironment(binary_path, self.timeout),
            QemuEnvironment(binary_path, self.timeout),
        ]

        for env in environments:
            if env.is_available():
                logger.info("Using %s", env.__class__.__name__)
                return env.execute()

        if not self.allow_host_execution:
            if not self._ask_user_permission():
                logger.error("No virtualization available and host execution denied")
                return None  # FIXME

        logger.info("Executing on host system , this will be fun ! ")
        host_env = HostEnvironment(binary_path, self.timeout)
        return host_env.execute()

    @staticmethod
    def _ask_user_permission() -> bool:
        # TODO: Flet alert support
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
