"""Build and run one PoC in the sandbox.

Owns the whole on-host build story for a downloaded exploit/PoC: the musl static
compile shim (so the produced binary runs in the minimal initrd), the
executable resolution, and handing the binary to the Isolate backend.
Expected failures, a failing compile, no executable produced, no sandbox
backend available, come back as a typed PocRunOutcome instead of
exceptions, so callers can persist and render them without try/except walls.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from config import COMPILE_TIMEOUT_SEC
from core.entities import SandboxRunResult
from isolate.isolate import Isolate, run_cmd, timeout_text

logger = logging.getLogger(f"kernel_audit.{__name__}")


@dataclass(frozen=True)
class PocRunOutcome:
    """Result of trying to build and run one PoC.

    Exactly one branch carries the outcome:
    sandbox set: the PoC was built and executed; command is the
    payload command that ran inside the sandbox.
    error set: the PoC never reached a sandbox (compile failure, no
    executable produced, or no backend available); the message is user-facing.
    neither set: there was nothing to build or run (no compile/test cmd).
    """

    sandbox: SandboxRunResult | None = None
    error: str | None = None
    command: str | None = None


def compile_poc(
    repo_path: Path,
    compile_cmd: str,
    timeout: int = COMPILE_TIMEOUT_SEC,
    on_output: Callable[[str], None] | None = None,
) -> None:
    """Run the PoC compile command inside its cloned repo directory.

    PoCs are built statically with musl-gcc: the qemu initrd is a minimal
    rootfs without glibc, and glibc-linked binaries abort there. A gcc/cc
    shim plus CC/CFLAGS force make-based builds to do the same.

    The build is bounded by timeout and killed as a whole process
    tree; on_output receives each stdout/stderr line as it is produced
    so the TUI can show live compile progress instead of a silent wait.
    """
    cmd = compile_cmd
    env = os.environ.copy()
    shim_dir: Path | None = None
    musl_gcc = shutil.which("musl-gcc")

    if musl_gcc:
        # direct gcc/cc invocations -> musl-gcc -static (only these get
        # the -static flag; make/other tools must not see it as an option)
        compiler_direct = bool(re.match(r"^\s*(?:gcc|cc)\s+", cmd))
        cmd = re.sub(r"^\s*(?:gcc|cc)\s+", "musl-gcc ", cmd, count=1)
        if compiler_direct and "-static" not in cmd and not re.search(
            r"-shared\b", cmd
        ):
            cmd = f"{cmd} -static"
        # musl-gcc is a thin wrapper that execs $REALGCC
        # point it at the real binary so a gcc/cc shim never recurses
        real_gcc = shutil.which("gcc")
        if real_gcc:
            env["REALGCC"] = real_gcc
        # Makefile builds call $(CC)/$(CFLAGS) or hardcode gcc; a shim
        # named gcc/cc forces every such invocation through musl-gcc -static
        # (glibc and dynamic-musl binaries abort in the minimal initrd)
        shim_dir = Path(tempfile.mkdtemp(prefix="kernaudit-cc-"))
        shim_script = f"#!/bin/sh\nexec {musl_gcc} -static \"$@\"\n"
        for name in ("gcc", "cc"):
            shim = shim_dir / name
            shim.write_text(shim_script)
            shim.chmod(0o755)
        env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"
        env["CC"] = "musl-gcc -static"
        env["CFLAGS"] = f"{env.get('CFLAGS', '')} -static".strip()

    try:
        proc = run_cmd(
            cmd,
            shell=True,
            cwd=repo_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            line_callback=on_output,
        )
    except subprocess.TimeoutExpired as exc:
        out_text, err_text = timeout_text(exc)
        partial = (err_text or out_text).strip()[:400]
        raise RuntimeError(
            f"compile timed out after {timeout}s\n{partial}"
        ) from exc
    finally:
        if shim_dir is not None:
            shutil.rmtree(shim_dir, ignore_errors=True)

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise RuntimeError(f"rc={proc.returncode}: {detail}")


def resolve_poc_binary(
    repo_path: Path,
    test_cmd: str | None,
    compile_cmd: str | None,
) -> Path | None:
    """Find the executable the compile/test steps produced in the repo."""
    name: str | None = None

    # the runnable the test step references (./prog -> prog)
    if test_cmd:
        match = re.match(r"^\s*\./(\S+)", str(test_cmd))
        if match:
            name = match.group(1)

    # else the -o output of the compile step
    if name is None and compile_cmd:
        match = re.search(r"(?<!\S)-o\s+(\S+)", str(compile_cmd))
        if match:
            name = match.group(1).rstrip(",;")

    # bare "gcc foo.c" (no -o) produces a.out
    if (
        name is None
        and compile_cmd
        and "gcc" in str(compile_cmd)
        and re.search(r"\.c\b", str(compile_cmd))
        and not re.search(r"(?<!\S)-o\b", str(compile_cmd))
    ):
        name = "a.out"

    if name:
        candidate = (repo_path / name).resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    # fall back to the newest executable at the repo root (e.g. make)
    best: Path | None = None
    try:
        for f in repo_path.iterdir():
            if f.is_file() and os.access(f, os.X_OK) and (
                best is None or f.stat().st_mtime > best.stat().st_mtime
            ):
                best = f
    except OSError:
        return None
    return best


class PoCRunner:
    """Build and run one PoC in the sandbox.

    all the build rules (musl static shim, CC/CFLAGS, executable
    resolution) and the sandbox selection sit behind a single run call,
    and expected failures come back as an outcome instead of exceptions.
    """

    def __init__(self, isolate: Isolate, timeout: int = COMPILE_TIMEOUT_SEC):
        self._isolate = isolate
        self._timeout = timeout

    def run(
        self,
        repo_path: Path,
        compile_cmd: str,
        test_cmd: str,
        on_output: Callable[[str], None] | None = None,
    ) -> PocRunOutcome:
        """Build the PoC on the host and run it in the sandbox.

        The build happens where the sources and toolchain exist; the qemu
        initrd ships no compiler, so only the produced binary is handed to
        the sandbox. A failing compile is a legitimate outcome, not an error.
        """
        if not (compile_cmd and str(compile_cmd).strip()) and not (
            test_cmd and str(test_cmd).strip()
        ):
            return PocRunOutcome()

        if compile_cmd and str(compile_cmd).strip():
            try:
                compile_poc(
                    repo_path,
                    str(compile_cmd),
                    timeout=self._timeout,
                    on_output=on_output,
                )
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("%s compile failed: %s", repo_path, exc)
                return PocRunOutcome(error=f"compile failed: {exc}")

        binary = resolve_poc_binary(
            repo_path, str(test_cmd or ""), str(compile_cmd or "")
        )
        if binary is None:
            return PocRunOutcome(error="no executable produced by the PoC build")

        command = str(test_cmd or f"./{binary.name}")

        try:
            logger.info("%s: %s - is started", repo_path, command)
            result = self._isolate.run_binary(binary)
            if result is None:
                return PocRunOutcome(
                    error=(
                        "no sandbox backend available "
                        "(virtme-ng/qemu missing and host denied)"
                    )
                )
            logger.info("%s poc - is finished", repo_path)
            return PocRunOutcome(sandbox=result, command=command)
        except (
            OSError,
            RuntimeError,
            subprocess.TimeoutExpired,
            ValueError,
            TypeError,
            KeyError,
            FileNotFoundError,
            PermissionError,
        ) as exc:
            # A failed sandbox run is a legitimate test outcome; keep the
            # user-facing summary at WARNING and the full traceback at DEBUG
            logger.warning("%s: %s - is failed: %s", repo_path, command, exc)
            logger.debug("sandbox failure traceback for %s", command, exc_info=True)
            return PocRunOutcome(error=str(exc))


__all__ = ["PoCRunner", "PocRunOutcome", "compile_poc", "resolve_poc_binary"]