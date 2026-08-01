import subprocess
from datetime import datetime

from isolate.isolate import ExecutionResult, IsolationEnvironment, logger
from isolate.parse_vm_internal_results import VIRTME_CRASH_PATTERNS, ParseVmResults


class VirtmeNGEnvironment(IsolationEnvironment):
    """
    this was the most stable solution,
    a lightweight virtualization of current environment, but
    better read docs here https://github.com/arighi/virtme-ng
    """

    def is_available(self) -> bool:
        # return shutil.which("virtme-ng") is not None
        return False  # FIXME

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
            crashed = ParseVmResults.detect_crash(result.stderr, VIRTME_CRASH_PATTERNS)

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
