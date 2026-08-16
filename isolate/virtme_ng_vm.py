import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from isolate.isolate import (
    ExecutionResult,
    IsolationEnvironment,
    _timeout_text,
    run_cmd,
)
from isolate.parse_vm_internal_results import VIRTME_CRASH_PATTERNS, ParseVmResults

# guest script run via `vng --run --exec`, emits the same section markers that
# qemu's guest script produces so ParseVmResults can extract the same data;
# virtme-ng shares the host filesystem copy-on-write, so no initrd is needed
VIRTME_GUEST_INIT = """#!/bin/bash
echo "========== VM START =========="
date
uname -a
cat /proc/version
echo "========== CMDLINE =========="
cat /proc/cmdline
echo "========== DMESG =========="
dmesg 2>/dev/null | tail -n 40
echo "========== MODULES =========="
cat /proc/modules 2>/dev/null
echo "========== RESOURCES =========="
cat /proc/loadavg
head -n 3 /proc/stat
echo "========== FILESYSTEM SNAPSHOT =========="
ls -la /
echo "========== PROCESS LIST =========="
ps -eo pid,user,comm 2>/dev/null | head -n 50
echo "========== BINARY OUTPUT START =========="
__POC__
EXITCODE=$?
echo "EXIT_CODE=$EXITCODE"
echo "========== BINARY OUTPUT END =========="
exit $EXITCODE
"""


class VirtmeNGEnvironment(IsolationEnvironment):
    """
    runs the target binary inside a virtme-ng guest that boots the running
    host kernel over a copy-on-write snapshot of the live filesystem,
    see docs https://github.com/arighi/virtme-ng

    `--run` boots the host kernel and `--exec` runs a command then exits,
    propagating the guest command exit code back to the host.
    """

    def __init__(
        self, binary_path: Path, timeout: int = 30, memory_mb: int = 512, cpus: int = 1
    ):
        super().__init__(binary_path, timeout)
        self.memory_mb = memory_mb
        self.cpus = cpus

    def is_available(self) -> bool:
        return shutil.which("virtme-ng") is not None

    def execute(self) -> ExecutionResult:
        start = time.perf_counter()
        self._log("stage", "virtme_execute_start")
        self._log("binary", str(self.binary_path))
        self._log("timeout", str(self.timeout))

        if not self.is_available():
            raise RuntimeError("virtme-ng dependencies missing")

        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            script = workdir / "audit.sh"
            script.write_text(
                VIRTME_GUEST_INIT.replace("__POC__", str(self.binary_path.absolute()))
            )
            script.chmod(0o755)

            stdout_log = workdir / "guest.log"
            stderr_log = workdir / "virtme.stderr"

            # redirect subprocess output to files instead of pipes: virtme-ng
            # warns about degraded redirection over pipes and may lose stderr
            cmd = [
                "virtme-ng",
                "--run",    # use the same current kernel
                "--quiet",
                "--memory",
                f"{self.memory_mb}M",
                "--cpus",
                str(self.cpus),
                "--exec",
                str(script),
            ]
            self._log("command", " ".join(cmd))
            self._log("stage", "vm_created")

            try:
                with stdout_log.open("wb") as out, stderr_log.open("wb") as err:
                    proc = run_cmd(
                        cmd,
                        cwd=workdir,
                        stdout=out,
                        stderr=err,
                        timeout=self.timeout,
                    )
                self._log("stage", "vm_finished")
                self._log("virtme_returncode", str(proc.returncode))

                stdout = stdout_log.read_text(errors="replace")
                stderr = stderr_log.read_text(errors="replace")
                self._log("stdout_size", str(len(stdout)))
                self._log("stderr_size", str(len(stderr)))

                kernel_info, resources, modules, files, processes = (
                    ParseVmResults().parse_guest_output(stdout, log=self._log)
                )
                exit_code = ParseVmResults.parse_exit_code(stdout)
                self._log("exit_code", str(exit_code))
                self._log("kernel_version", kernel_info.get("uname", "unknown"))

                duration = (time.perf_counter() - start) * 1000
                crashed = ParseVmResults.detect_crash(
                    stdout + stderr, VIRTME_CRASH_PATTERNS
                )
                # virtme-ng propagates the guest `exit $EXITCODE`, but trust the
                # guest's own echo over the host-side rc (mirrors qemu)
                returncode = (
                    exit_code if proc.returncode == 0 else proc.returncode
                )
                return ExecutionResult(
                    stdout=stdout,
                    stderr=stderr,
                    returncode=returncode,
                    execution_mode="virtme-ng",
                    duration_ms=duration,
                    crashed=crashed,
                    logs=self.logs,
                    kernel_info=kernel_info,
                    resources=resources,
                    modules=modules,
                    files=files,
                    processes=processes,
                )
            except subprocess.TimeoutExpired as exc:
                duration = (time.perf_counter() - start) * 1000
                stdout = stdout_log.read_text(errors="replace") if stdout_log.exists() else ""
                stderr = stderr_log.read_text(errors="replace") if stderr_log.exists() else ""
                self._log("stdout_size", str(len(stdout)))
                self._log("stderr_size", str(len(stderr)))
                out_text, err_text = _timeout_text(exc)
                partial = (err_text or out_text).strip()[:400]
                self._log("error", f"Timeout after {self.timeout}s")
                return ExecutionResult(
                    stdout=stdout,
                    stderr=(
                        f"Execution timeout ({self.timeout}s)\n"
                        f"{partial or 'no guest output captured'}"
                    ),
                    returncode=-1,
                    execution_mode="virtme-ng",
                    duration_ms=duration,
                    crashed=True,
                    logs=self.logs,
                )
