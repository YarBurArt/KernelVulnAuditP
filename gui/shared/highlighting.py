"""Regex rules for colored lists"""

import re

_MODULES_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<size>\d+)\s+(?P<count>\d+)\s+"
    r"(?P<used>[-\w,.]+)\s+(?P<state>\S+)\s+(?P<addr>0x[0-9a-f]+)"
)

_PROCESS_RE = re.compile(r"^\s*(?P<pid>\d+)\s+(?P<user>\S+)\s+(?P<comm>.*)$")

_FILE_RE = re.compile(
    r"^(?P<mode>[bcd-lps])\S{9}\s+\d+\s+(?P<owner>\S+)\s+(?P<group>\S+)\s+"
    r"(?P<size>\d+)\s+(?P<month>\S+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+"
    r"(?P<path>.*)$"
)

#: syntax-highlight config per list kind: (line regex, group->color)
LIST_RULES = {
    "modules": (
        _MODULES_RE,
        {
            "name": "name",
            "size": "badge",
            "count": "dim",
            "used": "dim",
            "state": "flag",
            "addr": "addr",
        },
    ),
    "process": (
        _PROCESS_RE,
        {"pid": "badge", "user": "dim", "comm": "name"},
    ),
    "file": (
        _FILE_RE,
        {
            "mode": "flag",
            "owner": "name",
            "group": "dim",
            "size": "badge",
            "month": "dim",
            "day": "dim",
            "time": "dim",
            "path": "path",
        },
    ),
}


def matched_ranges(
    rules: re.Pattern[str] | None,
    mapping: dict[str, str],
    line: str,
) -> list[tuple[int, int, str]]:
    """Map regex group spans to tuples on one line."""
    if rules is None:
        return []
    match = rules.match(line)
    if not match:
        return []
    ranges: list[tuple[int, int, str]] = []
    for group_name, color_name in mapping.items():
        start = match.start(group_name)
        stop = match.end(group_name)
        if start < 0 or stop <= start:
            continue
        ranges.append((start, stop, color_name))
    return ranges


def is_header_line(kind: str, line: str) -> bool:
    """Whether a line is a table header that should be dimmed as a whole."""
    return (
        (kind == "process" and "PID USER" in line)
        or (kind == "file" and line.startswith("total "))
    )


def colorize_line(kind: str, line: str) -> list[tuple[int, int, str]]:
    """Return the color ranges for one line of the given list kind."""
    rules, mapping = LIST_RULES.get(kind, (None, {}))
    ranges = matched_ranges(rules, mapping, line)
    if not ranges and is_header_line(kind, line):
        ranges = [(0, len(line), "dim")]
    return ranges