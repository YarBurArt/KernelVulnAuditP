"""Build and run one PoC in the sandbox.

Owns the whole on-host build story for a downloaded exploit/PoC:
the musl static compile shim
(so the produced binary runs in the minimal initrd), the
executable resolution, and handing the binary to the Isolate backend.
Expected failures, a failing compile, no executable produced, no sandbox
backend available, come back as a typed PocRunOutcome instead of
exceptions, so callers can persist and render them without try/except walls.
"""

import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from config import COMPILE_TIMEOUT_SEC
from core.entities import SandboxRunResult
from isolate.isolate import Isolate, run_cmd

logger = logging.getLogger(f"kernel_audit.{__name__}")

_ALLOWED_COMPILERS = frozenset(
    {
        "gcc",
        "cc",
        "clang",
        "clang++",
        "g++",
        "make",
        "cmake",
        "musl-gcc",
        "musl-clang",
        "go",
        "rustc",
        "cargo",
    }
)
_SHELL_METAS = re.compile(r"[;|&`$(){}[\]<>\\]")


def _validate_compile_tokens(tokens: list[str]) -> list[str]:
    """
    Raise ValueError if tokens look like shell injection
    or use a disallowed compiler
    """
    if not tokens:
        raise ValueError("Empty compile command")
    first = tokens[0].strip().lower()
    # absolute paths that end with an allowed compiler name
    basename = Path(first).name
    if basename not in _ALLOWED_COMPILERS:
        raise ValueError(f"Disallowed compiler/driver: {basename!r}")
    for tok in tokens:
        if _SHELL_METAS.search(tok):
            raise ValueError(
                f"Shell metacharacters detected in token: {tok!r}"
            )
    return tokens


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

    compile_cmd originates from random untrusted READMEs !
    """
    try:
        tokens = shlex.split(compile_cmd)
    except ValueError as exc:
        raise ValueError(f"Unparseable compile command: {exc}") from exc

    tokens = _validate_compile_tokens(tokens)
    musl_gcc = shutil.which("musl-gcc")
    env = os.environ.copy()
    shim_dir: Path | None = None

    if musl_gcc:
        # Rewrite first token if it is a plain gcc/cc
        first_lower = tokens[0].lower()
        if first_lower in ("gcc", "cc") or Path(first_lower).name in (
            "gcc",
            "cc",
        ):
            tokens[0] = musl_gcc
            if "-static" not in tokens and "-shared" not in tokens:
                tokens.append("-static")
        # musl-gcc is a thin wrapper that execs $REALGCC
        # point it at the real binary so a gcc/cc shim never recurses
        real_gcc = shutil.which("gcc")
        if real_gcc:
            env["REALGCC"] = real_gcc
        # Makefile builds call $(CC)/$(CFLAGS) or hardcode gcc; a shim
        # named gcc/cc forces every such invocation through musl-gcc -static
        # (glibc and dynamic-musl binaries abort in the minimal initrd)
        shim_dir = Path(tempfile.mkdtemp(prefix="kernaudit-cc-"))
        shim_script = f'#!/bin/sh\nexec {musl_gcc} -static "$@"\n'
        for name in ("gcc", "cc"):
            shim = shim_dir / name
            shim.write_text(shim_script)
            shim.chmod(0o755)
        env["PATH"] = f"{shim_dir}:{env.get('PATH', '')}"
        env["CC"] = "musl-gcc -static"
        env["CFLAGS"] = f"{env.get('CFLAGS', '')} -static".strip()

    try:
        run_cmd(
            tokens,  # each token is a literal argv element
            shell=False,
            cwd=repo_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            line_callback=on_output,
        )
    finally:
        if shim_dir is not None:
            shutil.rmtree(shim_dir, ignore_errors=True)


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
            if (
                f.is_file()
                and os.access(f, os.X_OK)
                and (best is None or f.stat().st_mtime > best.stat().st_mtime)
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
            return PocRunOutcome(
                error="no executable produced by the PoC build"
            )

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
            logger.debug(
                "sandbox failure traceback for %s", command, exc_info=True
            )
            return PocRunOutcome(error=str(exc))


__all__ = ["PoCRunner", "PocRunOutcome", "compile_poc", "resolve_poc_binary"]
