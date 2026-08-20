import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from core.entities import KernelInfo, RunLogs, SandboxRunResult, VmResources
from isolate.isolate import (
    ASSETS,
    IsolationEnvironment,
    _as_typed,
    run_cmd,
    timeout_text,
)
from isolate.parse_vm_internal_results import QEMU_CRASH_PATTERNS, ParseVmResults


class QemuEnvironment(IsolationEnvironment):
    def __init__(
        self, binary_path: Path, timeout: int = 30, memory_mb: int = 512, cpus: int = 1
    ):
        super().__init__(binary_path, timeout)
        self.memory_mb = memory_mb
        self.cpus = cpus
        self.assets = ASSETS

    def is_available(self) -> bool:
        return all(
            [
                shutil.which("qemu-system-x86_64") is not None,
                shutil.which("cpio") is not None,
                shutil.which("musl-gcc") is not None,
                shutil.which("busybox") is not None,
            ]
        )

    def execute(self) -> SandboxRunResult:
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
                proc = run_cmd(
                    cmd,
                    timeout=self.timeout,
                    text=True,
                    capture_output=True,
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
                # the qemu process itself always exits 0; the meaningful
                # outcome is the guest's EXIT_CODE echoed by the audit script
                returncode = exit_code if proc.returncode == 0 else proc.returncode
                return SandboxRunResult(
                    stdout=stdout,
                    stderr=proc.stderr,
                    returncode=returncode,
                    execution_mode="qemu",
                    duration_ms=duration,
                    crashed=crashed,
                    logs=_as_typed(RunLogs, self.logs),
                    kernel_info=_as_typed(KernelInfo, kernel_info),
                    resources=_as_typed(VmResources, resources),
                    modules=modules,
                    files=files,
                    processes=processes,
                )
            except subprocess.TimeoutExpired as exc:
                duration = (time.perf_counter() - start) * 1000
                stdout = (
                    serial_log.read_text(errors="replace")
                    if serial_log.exists()
                    else ""
                )
                out_text, err_text = timeout_text(exc)
                partial = (err_text or out_text).strip()[:400]
                self._log("stdout_size", str(len(stdout)))
                self._log("stderr_size", str(len(err_text)))
                return SandboxRunResult(
                    stdout=stdout,
                    stderr=(
                        f"execution timeout ({self.timeout}s)\n"
                        f"{partial or 'no qemu output captured'}"
                    ),
                    returncode=-1,
                    execution_mode="qemu",
                    duration_ms=duration,
                    crashed=True,
                    logs=_as_typed(RunLogs, self.logs),
                )

    def _build_initrd(self, workdir: Path) -> Path:
        """assembles a minimal rootfs with Busybox parts and the target binary of PoC,
        then packs into a cpio archive in tmp-like dir to early boot"""
        root = workdir / "rootfs"
        root.mkdir(parents=True, exist_ok=True)

        for d in ["bin", "sbin", "proc", "sys", "dev", "tmp", "etc"]:
            (root / d).mkdir(parents=True, exist_ok=True)

        self._install_busybox(root)
        self._install_runtime_libs(root)

        self._write_guest_init(root)
        self._write_guest_script(root)
        shutil.copy2(self.binary_path, root / self.binary_path.name)
        (root / self.binary_path.name).chmod(0o755)

        archive = workdir / "initrd.cpio"

        with archive.open("wb") as archive_file, subprocess.Popen(
            ["find", ".", "-print0"],
            cwd=root,
            stdout=subprocess.PIPE,
        ) as find_proc:
            assert find_proc.stdout is not None

            try:
                subprocess.run(
                    ["cpio", "--null", "-ov", "--format=newc"],
                    cwd=root,
                    stdin=find_proc.stdout,
                    stdout=archive_file,
                    stderr=subprocess.DEVNULL,
                    check=True,
                )
            finally:
                find_proc.stdout.close()

            find_proc.wait()

            if find_proc.returncode:
                raise subprocess.CalledProcessError(
                    returncode=find_proc.returncode,
                    cmd=find_proc.args,
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

    def _load_asset(self, name: str) -> str:
        path = self.assets / name
        if not path.exists():
            raise RuntimeError(f"qemu asset missing: {path}")
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

    def _install_runtime_libs(self, root: Path) -> None:
        """Copy the dynamic libraries needed by the guest binaries.

        The initrd is a minimal rootfs with no glibc, so both the nix-provided
        busybox (sh) and the target PoC would otherwise fail to load. ldd also
        reveals the ELF interpreter paths which are preserved as-is. Static
        binaries report a non-zero ldd status and are left alone.
        """
        targets = [root / "bin/busybox", self.binary_path]
        for binary in targets:
            if not binary.is_file():
                continue
            try:
                proc = subprocess.run(
                    ["ldd", str(binary)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            if proc.returncode != 0:
                continue

            for line in proc.stdout.splitlines():
                match = re.search(r"(/\S+\.so(?:\.\d+)*)", line)
                if not match:
                    continue
                src = Path(match.group(1))
                if not src.is_file():
                    continue
                dest = root / src.relative_to("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src, dest)
                except OSError:
                    continue

    @staticmethod
    def _find_kernel() -> Path:
        release = os.uname().release
        candidates = [
            Path("/boot/vmlinuz"),
            Path(f"/boot/vmlinuz-{release}"),
            Path("/boot/vmlinuz-linux"),
            Path("/run/booted-system/kernel"),
            Path(f"/lib/modules/{release}/vmlinuz"),
        ]
        for c in candidates:
            if c.exists():
                return c

        matches = sorted(Path("/boot").glob("vmlinuz*")) if Path("/boot").exists() else []
        if matches:
            return matches[-1]

        raise RuntimeError(
            "no kernel image found for qemu (looked in /boot, /run/booted-system, "
            "/lib/modules); install a kernel or set the vmlinuz path"
        )

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
