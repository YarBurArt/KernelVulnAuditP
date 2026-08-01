import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from isolate.isolate import ExecutionResult, IsolationEnvironment
from isolate.parse_vm_internal_results import QEMU_CRASH_PATTERNS, ParseVmResults


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

                exit_code = ParseVmResults.parse_exit_code(stdout)
                self._log("exit_code", str(exit_code))

                kernel_info, resources, modules, files, processes = (
                    ParseVmResults().parse_guest_output(stdout, log=self._log)
                )
                duration = (time.perf_counter() - start) * 1000
                crashed = ParseVmResults.detect_crash(
                    stdout + proc.stderr, QEMU_CRASH_PATTERNS
                )
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
