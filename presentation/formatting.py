"""Shared presentation formatting for the report, TUI, and CLI renderers.

Single home for status/severity classification, link extraction, and table
shaping so report/ and gui/ do not reimplement the same rules. Pure
presentation: these helpers read recommendation/row objects and produce
labels, keys, and display rows; they never touch the domain or adapters.
"""

from datetime import UTC, datetime
from typing import Any

# sort weight for status-based hardening rows (lower = more severe)
_SEV_RANK = {"FAIL": 0, "WARNING": 1, "OK": 2}

# statuses that mean a check is correctly satisfied
_OK_STATUSES = ("", "ok", "success", "pass")


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


def is_url(text: Any) -> bool:
    """Whether a string is a clickable URL."""
    if not isinstance(text, str):
        return False
    return text.startswith(("http://", "https://")) and len(text) > 8


def format_timestamp(ts: int, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str | None:
    """format timestamp to string"""
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(ts, tz=UTC)
        return dt.strftime(fmt)
    except ValueError:
        return None


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


def dict_to_display_rows(data: list[dict[str, Any]]) -> list[list[Any]]:
    """convert list of dicts to transposed table rows"""
    if not data:
        return []

    return [[key] + [d.get(key, "") for d in data] for key in data[0]]


def is_ok_status(status: Any) -> bool:
    """Whether a row status means the check is correctly satisfied."""
    return str(status or "").strip().lower() in _OK_STATUSES


def is_finding(status: Any) -> bool:
    """Whether a diff/row status represents a real finding"""
    return not is_ok_status(status)


def status_severity(status: Any) -> str:
    """Map a diff/row status to a severity class: CRIT/WARN/OK/INFO"""
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