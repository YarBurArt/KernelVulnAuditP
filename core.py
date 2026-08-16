"""
Core utility functions, more independent functionality
Date parsing, dict/list processing, text extraction, criticality calc.
"""

import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_CVSS_DICT_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_CVSS_LIST_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssV4_0")


def try_parse(date_str: str, fmt: str) -> datetime | None:
    try:
        # fmt may be naive; the result is normalized to UTC-aware below
        dt = datetime.strptime(date_str, fmt)  # noqa: DTZ007
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def parse_date_string(date_str: str) -> datetime | None:
    if not date_str:
        return None

    try:
        dt = datetime.fromisoformat(date_str)
    except ValueError:
        dt = None

    if dt is None:
        dt = try_parse(date_str, "%a %b %d %H:%M:%S %Y %z")

    if dt is None:
        base = date_str.split(".")[0]
        dt = try_parse(base, "%Y-%m-%dT%H:%M:%S")
        if dt is not None:
            dt = dt.replace(tzinfo=UTC)

    if dt is None:
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%d %b %Y %H:%M:%S",
            "%a, %d %b %Y %H:%M:%S %z",
            "%Y-%m-%d",
        ):
            dt = try_parse(date_str, fmt)
            if dt is not None:
                break

    if dt is None:
        return None

    return (
        dt.replace(tzinfo=UTC)
        if dt.tzinfo is None
        else dt.astimezone(UTC)
    )


def filter_items_by_date(
    items: list[dict[str, Any]],
    date_field: str = "published",
    min_timestamp: int | Any = None,
) -> list[dict[str, Any]]:
    """filter list of dicts by date field"""
    if min_timestamp is None:
        return items

    min_dt = datetime.fromtimestamp(min_timestamp, tz=UTC)
    result = []

    for item in items:
        cve_obj = item.get("cve", {}) if isinstance(item, dict) else {}
        date_str = None

        if cve_obj and date_field in cve_obj:
            date_str = cve_obj[date_field]
        elif isinstance(item, dict) and date_field in item:
            date_str = item[date_field]

        if not isinstance(date_str, str):
            continue

        dt = parse_date_string(date_str)
        if dt is None:
            continue

        if dt >= min_dt:
            result.append(item)

    return result


def format_timestamp(ts: int, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str | None:
    """format timestamp to string"""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return dt.strftime(fmt)
    except ValueError:
        return None


def dict_to_display_rows(data: list[dict[str, Any]]) -> list[list[Any]]:
    """convert list of dicts to transposed table rows"""
    if not data:
        return []

    return [[key] + [d.get(key, "") for d in data] for key in data[0]]


def flatten_dict_value(value: Any, max_length: int = 500) -> str:
    """convert dict/list to display string"""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        result = "\n".join(
            [", ".join(f"{ik}: {iv}" for ik, iv in it.items()) for it in value]
        )
    elif isinstance(value, dict):
        result = ", ".join(f"{k}: {v}" for k, v in value.items())
    elif isinstance(value, list):
        result = ", ".join(str(v) for v in value)
    else:
        result = str(value) if value is not None else ""

    return result[:max_length]


def merge_dicts_by_key(
    target: dict[str, Any], source: dict[str, Any], keys: list[str] | Any = None
) -> dict[str, Any]:
    """merge selected keys from source to target"""
    if keys is None:
        target.update(source)
    else:
        for key in keys:
            if key in source:
                target[key] = source[key]
    return target


def safe_get_nested(data: dict[str, Any], *keys, default: Any = None) -> Any:
    """safely get nested dict value"""
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def safe_get_attr(value: Any, key: str, default: Any = "") -> Any:
    """read an attribute from a dict or a dataclass-style object"""
    if isinstance(value, dict):
        result = value.get(key, default)
    else:
        result = getattr(value, key, default)
    return result if result is not None else default


def proc_module_name(entry: Any) -> str | None:
    """extract the module name from a /proc/modules-style line"""
    if not isinstance(entry, str):
        return None
    line = entry.strip()
    if not line:
        return None
    return line.split(None, 1)[0]


def strip_ansi_sequences(text: str) -> str:
    """remove ANSI escape codes"""
    ansi_pattern = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_pattern.sub("", text)


def extract_section_by_header(
    text: str, header_patterns: list[str], max_length: int = 500
) -> str | None:
    """extract text section by header pattern"""
    for pattern in header_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
        if matches:
            extracted = matches[0].strip()
            extracted = re.sub(r"\[.*?]\(.*?\)", "", extracted)
            extracted = extracted.replace("*", "").replace("`", "")
            extracted = " ".join(extracted.split())

            if 10 < len(extracted) < max_length:
                return extracted

    return None


def extract_code_block_commands(
    text: str, command_patterns: list[str], languages: list[str] | Any = None
) -> list[str]:
    """extract commands from Markdown code blocks"""
    commands = []

    lang_pattern = r"(?:" + "|".join(languages) + r")?" if languages else r""
    block_pattern = rf"`({lang_pattern})?\n(.*?)`"

    for block in re.findall(block_pattern, text, re.DOTALL):
        content = block[1] if isinstance(block, tuple) else block
        for pattern in command_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            commands.extend(matches)

    return commands


def clean_command_string(cmd: str) -> str:
    """clean command string from Markdown"""
    cmd = cmd.replace("`", "").replace("`", "")
    cmd = cmd.split("\n")[0]
    return cmd.strip()


def parse_key_with_brackets(raw_key: str) -> tuple:
    """parse key with bracket notation: key, key[], key[name]"""
    match = re.fullmatch(r"([^\[]+)(?:\[(.*?)])?", raw_key)
    if not match:
        return raw_key, None
    return match.group(1), match.group(2)


def ensure_list_in_dict(container: dict[str, Any], key: str, value: Any) -> None:
    """ensure key contains list, append value"""
    if key not in container:
        container[key] = [value]
    else:
        if not isinstance(container[key], list):
            container[key] = [container[key]]
        container[key].append(value)


def assign_value_by_key_type(
    results: dict[str, Any], base: str, inner: str | None, value: str
) -> None:
    """assign value based on key type: scalar, list, or dict"""
    if inner is None:  # key=value
        if base in results:
            ensure_list_in_dict(results, base, value)
        else:
            results[base] = value
    elif inner == "":  # key[]=value
        ensure_list_in_dict(results, base, value)
    else:  # key[name]=value
        if base not in results:
            results[base] = {}
        if not isinstance(results[base], dict):
            raise ValueError(f"Key '{base}' used as both scalar/list and dict")
        results[base][inner] = value


def parse_key_value_pairs(
    blob: str, separator: str = ";", kv_delim: str = ":"
) -> dict[str, str]:
    """parse key:value;key:value blob"""
    result = {}
    for pair in blob.split(separator):
        if kv_delim in pair:
            key, value = pair.split(kv_delim, 1)
            result[key.strip()] = value.strip()
    return result


def calculate_criticality_score(data: dict[str, Any]) -> int:
    """calc criticality score in range 0..100."""

    def clamp(value: int) -> int:
        return max(0, min(100, value))

    def as_float(value: Any) -> float:
        try:
            return float(value)
        except TypeError, ValueError:
            return 0.0

    score = 0

    cvss = as_float(data.get("cvss_v3_score") or data.get("cvss_v2_score"))
    severity = (data.get("severity") or "").upper()

    if cvss >= 9.0:
        score += 65
        score += int((cvss - 9.0) * 10)  # 9.8 -> +8
    elif cvss >= 7.0:
        score += 45
        score += int((cvss - 7.0) * 10)
    elif cvss >= 4.0:
        score += 20
        score += int((cvss - 4.0) * 8)
    elif cvss > 0:
        score += int(cvss * 4)

    if severity == "CRITICAL":
        score += 10
    elif severity == "HIGH":
        score += 5

    if data.get("in_cisa_kev"):
        score += 20
        if data.get("known_ransomware"):
            score += 10

    if data.get("has_exploit"):
        score += 15
        score += min(int(data.get("exploit_count") or 0) * 2, 10)

    score += min(int(data.get("github_refs") or 0) * 2, 10)
    score += min(int(data.get("exploitdb_refs") or 0) * 2, 10)

    return clamp(score)


def chain_get(
    data: dict[str, Any], path: str, default: Any = None, separator: str = "."
) -> Any:
    """get nested value using dot notation"""
    keys = path.split(separator)
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list):
            try:
                idx = int(key)
                current = current[idx]
            except ValueError, IndexError:
                return default
        else:
            return default

    return current


def filter_list_by_pred(
    items: list[Any], predicate: Callable, limit: int | Any = None
) -> list[Any]:
    """filter list by predicate with optional limit"""
    result = [item for item in items if predicate(item)]
    if limit is not None:
        result = result[:limit]
    return result


def group_by_key(
    items: list[dict[str, Any]], key: str
) -> dict[str, list[dict[str, Any]]]:
    """group list of dicts by key"""
    result: dict[Any, list[dict[str, Any]]] = {}
    for item in items:
        group_key = item.get(key)
        if group_key is not None:
            if group_key not in result:
                result[group_key] = []
            result[group_key].append(item)
    return result


def count_by_key(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    """count occurrences by key"""
    result: dict[Any, int] = {}
    for item in items:
        value = item.get(key)
        if value is not None:
            result[value] = result.get(value, 0) + 1
    return result


def update_config_file(config_path: Path, updates: dict[str, str]) -> None:
    """
    update config by dict of {VAR_NAME: new_value}
    where value includes quotes if needed
    """
    config_path = Path(config_path)
    config_content = config_path.read_text(encoding="utf-8")

    for key, replacement in updates.items():
        if replacement.isdigit() or (
            replacement.startswith("-") and replacement[1:].isdigit()
        ):
            pattern = rf"^{key}\s*=\s*\d+"
        elif replacement in ("True", "False"):
            pattern = rf"^{key}\s*=\s*(True|False)"
        else:
            pattern = rf'^{key}\s*=\s*["\'].*["\']'

        config_content = re.sub(
            pattern, f"{key} = {replacement}", config_content, flags=re.MULTILINE
        )

    config_path.write_text(config_content, encoding="utf-8")


def format_report(data: dict) -> dict:
    """filter data to format useful report"""
    feeds = data.get("feeds", {}) or {}
    findings = feeds.get("findings", [])
    pocs = feeds.get("pocs", [])

    nist_count = 0
    osv_count = 0

    for f in findings:
        src = (f.get("source") or "").upper()
        if src == "NIST":
            nist_count += 1
        elif src == "OSV":
            osv_count += 1

    return {
        "kernel": data.get("kernel", ""),
        "system": data.get("system", ""),
        "build_date": data.get("build_date", 0),
        "nist_count": nist_count,
        "osv_count": osv_count,
        "github_count": len(pocs),
    }


def summarize_sandbox(result) -> dict[str, Any]:
    """summarize sandbox result by reformat and filter"""
    return {
        "mode": getattr(result, "execution_mode", "unknown"),
        "returncode": getattr(result, "returncode", None),
        "success": getattr(result, "returncode", 1) == 0,
        "crashed": getattr(result, "crashed", False),
        "stdout": getattr(result, "stdout", " "),
        "stderr": getattr(result, "stderr", " "),
        "logs": getattr(result, "logs", {}),
        "kernel_info": getattr(result, "kernel_info", {}),
        "resources": getattr(result, "resources", {}),
        "modules": getattr(result, "modules", []),
        "files": getattr(result, "files", []),
        "processes": getattr(result, "processes", []),
    }


def norm_sysctl_value(value: Any) -> str:
    """normalize sysctl possible values for kernel params check"""
    if value is None:
        return ""
    text = str(value).strip().strip('"').strip("'")
    if not text:
        return ""
    low = text.lower()
    if low in ("yes", "true", "on", "enabled"):
        return "1"
    if low in ("no", "false", "off", "disabled"):
        return "0"
    if re.fullmatch(r"[+-]?\d+", text):
        return str(int(text))
    return low

def extract_cvss(metrics: Any) -> tuple[Any, Any, Any]:
    """extract (base_score, severity, vector) from CVSS metrics"""
    if isinstance(metrics, dict):
        for metric_key in _CVSS_DICT_KEYS:
            for m in metrics.get(metric_key, []):
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore")
                if score is not None:
                    return (
                        score,
                        cvss_data.get("baseSeverity"),
                        cvss_data.get("vectorString"),
                    )
        return None, None, None

    for metric in metrics or []:
        for cvss_key in _CVSS_LIST_KEYS:
            cvss_data = metric.get(cvss_key)
            if cvss_data:
                score = cvss_data.get("baseScore")
                if score is not None:
                    return (
                        score,
                        cvss_data.get("baseSeverity"),
                        cvss_data.get("vectorString"),
                    )
    return None, None, None


CVE_RE = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    """extract all CVE ids from text via CVE_RE"""
    return list(CVE_RE.findall(text))


def extract_english_description(descriptions: Any) -> str:
    """extract the english description from a CVE descriptions list"""
    descriptions = descriptions or []
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            value = item.get("value")
            if value:
                return str(value)
    if descriptions:
        first = descriptions[0]
        if isinstance(first, dict):
            return str(first.get("value") or "")
    return ""


# Shared formatting helpers for report and UI
# the VM guest script wraps the payload between these two lines
_BINARY_OUTPUT_START = "========== BINARY OUTPUT START =========="
_BINARY_OUTPUT_END = "========== BINARY OUTPUT END =========="

# sort weight for status-based hardening rows (lower = more severe)
_SEV_RANK = {"FAIL": 0, "WARNING": 1, "OK": 2}

# statuses that mean a check is correctly satisfied
_OK_STATUSES = ("", "ok", "success", "pass")


def is_url(text: Any) -> bool:
    """Whether a string is a clickable URL."""
    if not isinstance(text, str):
        return False
    return text.startswith(("http://", "https://")) and len(text) > 8


def is_ok_status(status: Any) -> bool:
    """Whether a row status means the check is correctly satisfied."""
    return str(status or "").strip().lower() in _OK_STATUSES


def is_finding(status: Any) -> bool:
    """Whether a diff/row status represents a real finding"""
    return not is_ok_status(status)


def status_severity(status: Any) -> str:
    """Map a diff/row status to a severity class: CRIT/WARN/OK/INFO with colors"""
    up = str(status or "").upper()
    if up in ("FAIL", "NEW", "CRIT", "CRITICAL", "MISMATCH"):
        return "CRIT"
    if up in ("WARNING", "WARN", "MISSING", "REMOVED"):
        return "WARN"
    if up in ("OK", "SUCCESS"):
        return "OK"
    return "INFO"


def audit_priority(rec: Any) -> tuple[int, str]:
    """Sort key for hardening recommendations (diff-based severity)."""
    try:
        expected = int(safe_get_attr(rec, "expected_value"))
        actual = int(safe_get_attr(rec, "actual_value"))
        diff = abs(expected - actual)
        if diff >= 2:
            return 0, "CRIT"
        if diff == 1:
            return 1, "WARN"
    except (TypeError, ValueError):
        pass
    return 2, "INFO"


def status_rank(rec: Any) -> int:
    """Sort key for SELinux/capability host info recommendations"""
    return _SEV_RANK.get(str(safe_get_attr(rec, "status", "")).upper(), 2)


def rec_severity(rec: Any) -> tuple[str, str]:
    """Return severity for a recommendation.
    The expected/actual diff drives CRIT/WARN when both values parse as
    numbers; otherwise the status field decides. Kernel hardening rows use
    ok / mismatch / missing so every non-ok row is flagged
    """
    try:
        diff = abs(
            int(float(safe_get_attr(rec, "expected_value")))
            - int(float(safe_get_attr(rec, "actual_value")))
        )
        if diff >= 2:
            return "CRIT", "crit"
        if diff == 1:
            return "WARN", "warn"
    except (TypeError, ValueError):
        pass

    status = str(safe_get_attr(rec, "status", ""))
    if status == "FAIL":
        return "CRIT", "crit"
    if status in ("WARNING", "mismatch", "missing"):
        return "WARN", "warn"
    return "INFO", "info"


def suggestion_for(rec: Any) -> str:
    """Extract the readable suggestion/details from a recommendation"""
    raw = safe_get_attr(rec, "raw_data", {}) or {}
    if not isinstance(raw, dict):
        raw = {}
    suggestion = raw.get("suggestion", raw.get("details", raw.get("solution", "")))
    if not suggestion:
        suggestion = safe_get_attr(rec, "description", "")
    suggestion = str(suggestion or "").strip()
    if suggestion.lower() == "no description":
        suggestion = ""
    if not suggestion:
        related = str(raw.get("related", "") or "")
        if related:
            suggestion = f"Check with: {related}"
        else:
            suggestion = "See the docs section for details"
    return suggestion or "N/A"


def rec_context_rows(rec: Any) -> list[str]:
    """Extra "who/what is affected" lines for a recommendation's details"""
    raw = safe_get_attr(rec, "raw_data", {}) or {}
    if not isinstance(raw, dict):
        raw = {}
    rows: list[str] = []
    source = str(safe_get_attr(rec, "source", ""))
    if source == "selinux":
        section = raw.get("section")
        if section:
            rows.append(f"Section: {section}")
        persistent = raw.get("persistent")
        if persistent:
            rows.append(f"Persistent: {persistent}")
    elif source in ("proc", "getcap"):
        username = raw.get("username") or raw.get("owner_name")
        if username:
            rows.append(f"User: {username}")
        pid = raw.get("pid")
        if pid:
            rows.append(f"PID: {pid}")
    return rows


def extract_links(rec: Any) -> list[str]:
    """Unique http(s) links attached to a recommendation or diff row.

    Reads the usual raw_data keys (solution/details/suggestion/link/url)
    plus a links list, and the top-level link / links keys used by
    the report diff rows.
    """
    raw = safe_get_attr(rec, "raw_data", {}) or {}
    if not isinstance(raw, dict):
        raw = {}
    candidates = [
        raw.get("solution"),
        raw.get("details"),
        raw.get("suggestion"),
        raw.get("link"),
        raw.get("url"),
    ]
    candidates += list(raw.get("links", []) or [])
    candidates.append(safe_get_attr(rec, "link", ""))
    candidates += list(safe_get_attr(rec, "links", []) or [])
    out: list[str] = []
    for candidate in candidates:
        text = str(candidate or "").strip()
        if is_url(text) and text not in out:
            out.append(text)
    return out


def dedupe_links(items: list[Any]) -> list[str]:
    """Deduplicated, stable-ordered list of links across recommendations"""
    out: list[str] = []
    for item in items or []:
        for link in extract_links(item):
            if link not in out:
                out.append(link)
    return out


def binary_output(stdout: str) -> str:
    """Filter VM logs: keep only the payload between the binary output markers."""
    start = stdout.find(_BINARY_OUTPUT_START)
    end = stdout.find(_BINARY_OUTPUT_END)
    if start == -1 or end == -1:
        return stdout.strip()
    body = stdout[start + len(_BINARY_OUTPUT_START):end]
    lines = [ln for ln in body.splitlines() if not ln.startswith("EXIT_CODE=")]
    return "\n".join(lines).strip()


def format_run_timestamp(ts: Any) -> str:
    """Format an ISO timestamp just as HH:MM:SS"""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(str(ts))
        return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return str(ts)[:19]


def short_hash(value: Any) -> str:
    """Truncate an exploit file hash to 12 chars for headers"""
    return (value or "")[:12] or "N/A"


def format_kernel_line(kernel_info: dict) -> str:
    """kernel line for a sandbox run details."""
    return kernel_info.get("uname", kernel_info.get("date", "N/A"))


def first_resource_line(resource: str | None) -> str | None:
    """First line of a meminfo/cpuinfo blob"""
    if not resource:
        return None
    return resource.split("\n")[0] if "\n" in resource else resource[:200]


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

    Mirrors every field persisted by AppServices._store_sandbox_run so
    the log keeps all data, just re-laid out instead of a dict repr.
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
        add(f"kernel_info:   {format_kernel_line(kernel_info)}")
    resources = data.get("resources") or {}
    mem = first_resource_line(resources.get("meminfo"))
    cpu = first_resource_line(resources.get("cpuinfo"))
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


def format_execution_report(report: dict[str, Any]) -> str:
    """Render the execution-tests report as readable, detailed DEBUG log text.

    Every piece of data in the report is preserved (CVE metadata, PoC
    metadata, sandbox IO, kernel info, resources, module/process/file
    lists); it is only re-laid out as labeled sections instead of the raw
    report dict.
    """
    lines: list[str] = []
    add = lines.append
    add("=== Execution Report ===")
    add(f"Kernel:   {report.get('kernel', 'N/A')}")
    add(f"Build:    {report.get('build_date', 'N/A')}")
    add(f"CVEs:     {report.get('cves_processed', 0)}")

    stats = report.get("stats") or {}
    if stats:
        add("Stats:")
        add(
            "  total:        {}\n"
            "  with_exploits:{}\n"
            "  in_cisa_kev:  {}\n"
            "  ransomware:   {}\n"
            "  critical:     {}\n"
            "  avg_cvss:     {}".format(
                stats.get("total", 0),
                stats.get("with_exploits", 0),
                stats.get("in_cisa_kev", 0),
                stats.get("ransomware_related", 0),
                stats.get("critical_count", 0),
                stats.get("avg_cvss", 0),
            )
        )
        if stats.get("by_severity"):
            add("  by_severity:")
            add(_debug_mapping(stats["by_severity"], 4))
        if stats.get("security_recommendations"):
            add("  security_recommendations:")
            add(_debug_mapping(stats["security_recommendations"], 4))

    entries = report.get("entries") or []
    add(f"Entries:  {len(entries)}")
    for index, entry in enumerate(entries, 1):
        add("")
        add(
            f"[{index}] CVE {entry.get('cve_id', 'N/A')} | "
            f"{entry.get('severity', 'N/A')} | "
            f"CVSS {entry.get('cvss_v3_score', 'N/A')}"
        )
        description = str(entry.get("description") or "").strip()
        if description:
            add(f"    Description: {description}")
        sources = entry.get("sources") or []
        if sources:
            add(f"    Sources:     {', '.join(str(s) for s in sources)}")
        pocs = entry.get("pocs") or []
        if not pocs:
            add("    PoCs:        none")
        for poc in pocs:
            add(
                f"    PoC: {poc.get('url', 'N/A')} "
                f"[{poc.get('language', '?')} stars:{poc.get('stars', 0)}]"
            )
            if poc.get("compile_cmd"):
                add(f"      compile: {poc['compile_cmd']}")
            if poc.get("test_cmd"):
                add(f"      test:    {poc['test_cmd']}")
            if poc.get("sandbox_error"):
                add(f"      sandbox error: {poc['sandbox_error']}")
                continue
            sandbox = poc.get("sandbox")
            if not isinstance(sandbox, dict):
                continue
            add(
                f"      sandbox: mode={sandbox.get('mode', 'unknown')} "
                f"returncode={sandbox.get('returncode')} "
                f"success={sandbox.get('success')} "
                f"crashed={sandbox.get('crashed')}"
            )
            logs = sandbox.get("logs") or {}
            exploit_hash = logs.get("exploit_hash", logs.get("binary", ""))
            if exploit_hash:
                add(f"      exploit hash: {exploit_hash}")
            kernel_info = sandbox.get("kernel_info") or {}
            if kernel_info:
                add(f"      kernel: {format_kernel_line(kernel_info)}")
                extra = {k: v for k, v in kernel_info.items() if k not in ("uname", "date")}
                if extra:
                    add("      kernel_info:")
                    add(_debug_mapping(extra, 8))
            resources = sandbox.get("resources") or {}
            if resources:
                add("      resources:")
                add(_debug_mapping(resources, 8))
            modules = sandbox.get("modules") or []
            if modules:
                add(f"      modules ({len(modules)}): {', '.join(str(m) for m in modules)}")
            processes = sandbox.get("processes") or []
            if processes:
                add(
                    f"      processes ({len(processes)}): "
                    f"{', '.join(str(p) for p in processes)}"
                )
            files = sandbox.get("files") or []
            if files:
                add(f"      files ({len(files)}): {', '.join(str(f) for f in files)}")
            for key, label in (("stdout", "STDOUT"), ("stderr", "STDERR")):
                blob = sandbox.get(key)
                if blob:
                    add(f"      {label}:")
                    add(_debug_indent(blob, 8))
    return "\n".join(lines)
