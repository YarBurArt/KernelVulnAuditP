"""Rendering of sandbox run results into human-readable text and log lines.

Consumes the typed core.entities.SandboxRunResult and the persisted
core.entities.SandboxRun (or dict-compatible projections) and
lays them out for DEBUG logs, the execution report, and the TUI/CLI sandbox
views.
"""

import logging
from dataclasses import asdict
from typing import Any

from core.entities import ExecutionReport

# the VM guest script wraps the payload between these two lines
_BINARY_OUTPUT_START = "========== BINARY OUTPUT START =========="
_BINARY_OUTPUT_END = "========== BINARY OUTPUT END =========="


def binary_output(stdout: str) -> str:
    """Filter VM logs: keep only the payload between the binary output markers."""
    start = stdout.find(_BINARY_OUTPUT_START)
    end = stdout.find(_BINARY_OUTPUT_END)
    if start == -1 or end == -1:
        return stdout.strip()
    body = stdout[start + len(_BINARY_OUTPUT_START):end]
    lines = [ln for ln in body.splitlines() if not ln.startswith("EXIT_CODE=")]
    return "\n".join(lines).strip()


def _debug_indent(text: Any, spaces: int = 2) -> str:
    """Indent every line of text for a log blob."""
    pad = " " * spaces
    return "\n".join(f"{pad}{line}" for line in str(text).splitlines())


def _debug_mapping(value: Any, spaces: int = 2) -> str:
    """Render a nested dict/list as aligned key: value log lines."""
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{' ' * spaces}{key}:")
                lines.append(_debug_mapping(item, spaces + 2))
            else:
                text = str(item)
                if "\n" in text:
                    lines.append(f"{' ' * spaces}{key}:")
                    lines.append(_debug_indent(text, spaces + 2))
                else:
                    lines.append(f"{' ' * spaces}{key}: {text}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(item, (dict, list)) for item in value):
            return ", ".join(str(item) for item in value)
        return "\n".join(_debug_mapping(item, spaces) for item in value)
    return str(value)


def format_sandbox_detail(data: dict[str, Any]) -> str:
    """Render one stored sandbox run as labeled DEBUG log lines.

    Mirrors every field persisted by the execution service so the log keeps
    all data, just re-laid out instead of a dict repr.
    """
    lines: list[str] = []
    add = lines.append
    add(f"platform:      {data.get('sandbox_platform', 'unknown')}")
    add(f"timestamp:     {data.get('run_timestamp', '')}")
    add(f"exploit hash:  {data.get('exploit_file_hash', '')}")
    add(f"success:       {data.get('execution_success', False)}")
    add(f"exit_code:     {data.get('exit_code', '')}")
    add(f"crashed:       {data.get('crashed', False)}")
    if data.get("stdin"):
        add(f"command:       {data.get('stdin')}")
    if data.get("notes"):
        add(f"notes:         {data.get('notes')}")
    kernel_info = data.get("kernel_info") or {}
    if kernel_info:
        add(f"kernel_info:   {_kernel_line(kernel_info)}")
    resources = data.get("resources") or {}
    mem = first_line(resources.get("meminfo"))
    cpu = first_line(resources.get("cpuinfo"))
    if mem:
        add(f"memory:        {mem}")
    if cpu:
        add(f"cpu:           {cpu}")
    modules = data.get("modules") or []
    if modules:
        add(f"modules ({len(modules)}):      {', '.join(str(m) for m in modules)}")
    processes = data.get("open_processes") or []
    if processes:
        add(
            f"processes ({len(processes)}):  "
            f"{', '.join(str(p) for p in processes)}"
        )
    files = data.get("open_files") or []
    if files:
        add(f"files ({len(files)}):        {', '.join(str(f) for f in files)}")
    for key, label in (("stdout", "STDOUT"), ("stderr", "STDERR")):
        blob = data.get(key)
        if blob:
            add(f"{label}:")
            add(_debug_indent(blob, 2))
    return "\n".join(lines)


def log_sandbox_run(logger: logging.Logger, cve_id: str, data: dict[str, Any]) -> None:
    """Emit a stored sandbox run as separate DEBUG records, one per field.

    Replaces the single unreadable dict dump with several log records so
    no field is lost while the log stays greppable: scalars become one line,
    nested dicts/lists are laid out key-per-record, and multi-line blobs
    (stdout/stderr/notes) are split line-by-line. Skipped from the TUI
    console, same as the other verbose sandbox dump.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    extra = {"skip_console": True}
    logger.debug("%s isolated sandbox run:", cve_id, extra=extra)
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            if not value:
                logger.debug("  %s: %r", key, value, extra=extra)
                continue
            logger.debug("  %s:", key, extra=extra)
            for line in _debug_mapping(value, 4).splitlines():
                logger.debug("%s", line, extra=extra)
        elif isinstance(value, str) and "\n" in value:
            logger.debug("  %s:", key, extra=extra)
            for line in value.splitlines():
                logger.debug("%s", _debug_indent(line, 4), extra=extra)
        else:
            logger.debug("  %s: %s", key, value, extra=extra)


def format_execution_report(report: ExecutionReport) -> str:
    """Render the execution-tests report as readable, detailed DEBUG log text.

    Every piece of data in the report is preserved (CVE metadata, PoC
    metadata, sandbox IO, kernel info, resources, module/process/file
    lists); it is only re-laid out as labeled sections instead of the raw
    report dict.
    """
    lines: list[str] = []
    add = lines.append
    add("=== Execution Report ===")
    add(f"Kernel:   {report.kernel or 'N/A'}")
    add(f"Build:    {report.build_date or 'N/A'}")
    add(f"CVEs:     {report.cves_processed}")

    stats = report.stats
    add("Stats:")
    add(
        f"  total:        {stats.total}\n"
        f"  with_exploits:{stats.with_exploits}\n"
        f"  in_cisa_kev:  {stats.in_cisa_kev}\n"
        f"  ransomware:   {stats.ransomware_related}\n"
        f"  critical:     {stats.critical_count}\n"
        f"  avg_cvss:     {stats.avg_cvss}"
    )
    if stats.by_severity:
        add("  by_severity:")
        add(_debug_mapping(stats.by_severity, 4))

    entries = report.entries
    add(f"Entries:  {len(entries)}")
    for index, entry in enumerate(entries, 1):
        add("")
        add(
            f"[{index}] CVE {entry.cve_id or 'N/A'} | "
            f"{entry.severity or 'N/A'} | "
            f"CVSS {entry.cvss_v3_score if entry.cvss_v3_score is not None else 'N/A'}"
        )
        description = str(entry.description or "").strip()
        if description:
            add(f"    Description: {description}")
        sources = entry.sources
        if sources:
            add(f"    Sources:     {', '.join(str(s) for s in sources)}")
        pocs = entry.pocs
        if not pocs:
            add("    PoCs:        none")
        for poc in pocs:
            add(
                f"    PoC: {poc.url or 'N/A'} "
                f"[{poc.language or '?'} stars:{poc.stars}]"
            )
            if poc.compile_cmd:
                add(f"      compile: {poc.compile_cmd}")
            if poc.test_cmd:
                add(f"      test:    {poc.test_cmd}")
            if poc.sandbox_error:
                add(f"      sandbox error: {poc.sandbox_error}")
                continue
            sandbox = poc.sandbox
            if sandbox is None:
                continue
            add(
                f"      sandbox: mode={sandbox.execution_mode} "
                f"returncode={sandbox.returncode} "
                f"success={sandbox.success} "
                f"crashed={sandbox.crashed}"
            )
            if sandbox.logs.binary:
                add(f"      exploit hash: {sandbox.logs.binary}")
            kernel_info = sandbox.kernel_info
            if kernel_info:
                add(f"      kernel: {_kernel_line(asdict(kernel_info))}")
                extra = {
                    k: v
                    for k, v in asdict(kernel_info).items()
                    if k not in ("uname", "date")
                }
                if extra:
                    add("      kernel_info:")
                    add(_debug_mapping(extra, 8))
            resources = asdict(sandbox.resources)
            if any(resources.values()):
                add("      resources:")
                add(_debug_mapping(resources, 8))
            modules = sandbox.modules
            if modules:
                add(f"      modules ({len(modules)}): {', '.join(str(m) for m in modules)}")
            processes = sandbox.processes
            if processes:
                add(
                    f"      processes ({len(processes)}): "
                    f"{', '.join(str(p) for p in processes)}"
                )
            files = sandbox.files
            if files:
                add(f"      files ({len(files)}): {', '.join(str(f) for f in files)}")
            for key, label in (("stdout", "STDOUT"), ("stderr", "STDERR")):
                blob = getattr(sandbox, key)
                if blob:
                    add(f"      {label}:")
                    add(_debug_indent(blob, 8))
    return "\n".join(lines)


def _kernel_line(kernel_info: Any) -> str:
    """Best-effort short kernel identifier from a kernel_info mapping."""
    if isinstance(kernel_info, dict):
        return str(kernel_info.get("uname", kernel_info.get("date", "N/A")))
    return str(
        getattr(kernel_info, "uname", None) or getattr(kernel_info, "date", "N/A")
    )


def first_line(resource: Any) -> str | None:
    """First line of a meminfo/cpuinfo blob"""
    if not resource:
        return None
    return str(resource).split("\n")[0] if "\n" in str(resource) else str(resource)[:200]