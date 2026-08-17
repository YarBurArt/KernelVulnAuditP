"""Report export helpers: render and save a report as txt / JSON / YAML.

The main CLI and the report package entry share these helpers so every
report-producing path behaves the same: build the data dict once, render it
in the requested format, save it to a file and (unless quiet) print it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import term

REPORT_FORMATS = ("txt", "json", "yaml")

_DEFAULT_PATHS = {
    "txt": "report_data.txt",
    "json": "report_data.json",
    "yaml": "report_data.yaml",
}


def default_report_path(fmt: str) -> str:
    """Default report filename for a format (JSON keeps the historical name)."""
    return _DEFAULT_PATHS[fmt.lower()]


def _validate_format(fmt: str) -> str:
    fmt = (fmt or "txt").strip().lower()
    if fmt not in REPORT_FORMATS:
        raise ValueError(
            f"Unsupported report format: {fmt!r} "
            f"(choose from {', '.join(REPORT_FORMATS)})"
        )
    return fmt


def resolve_report_path(path: str | Path | None, fmt: str) -> Path:
    """Validate fmt and normalize the output path.

    A path without a suffix gets the format extension appended so
    -o /tmp/audit --format yaml writes /tmp/audit.yaml.
    """
    fmt = _validate_format(fmt)
    p = Path(path or default_report_path(fmt))
    if not p.suffix:
        p = p.with_suffix(f".{fmt}")
    return p


def render_report(
    data: dict[str, Any],
    fmt: str,
    verbose: bool = False,
    color: bool = False,
) -> str:
    """Serialize the report data dict into a txt / JSON / YAML string."""
    fmt = _validate_format(fmt)
    if fmt == "txt":
        from report.cli import CLIReportRenderer

        return CLIReportRenderer(data, verbose=verbose, color=color).build_full_report()
    if fmt == "json":
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)
    if fmt == "yaml":
        import yaml

        return yaml.safe_dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
    raise ValueError(f"Unsupported report format: {fmt!r}")


def save_report(
    data: dict[str, Any],
    path: str | Path | None,
    fmt: str,
    verbose: bool = False,
) -> Path:
    """Write the report to path in format fmt (no ANSI colors)."""
    fmt = _validate_format(fmt)
    p = resolve_report_path(path, fmt)
    p.parent.mkdir(parents=True, exist_ok=True)
    text = render_report(data, fmt, verbose=verbose, color=False)
    p.write_text(text, encoding="utf-8")
    return p


def emit_report(
    data: dict[str, Any],
    output: str | Path | None = None,
    fmt: str = "txt",
    verbose: bool = False,
    quiet: bool = False,
) -> Path:
    """Save the report to a file and, unless quiet, print it too.

    Returns the saved path. txt output is rendered without ANSI codes
    for the file and with terminal colors when printed.
    """
    fmt = _validate_format(fmt)
    path = save_report(data, output, fmt, verbose=verbose)
    if not quiet:
        color = term.supports_color()
        term.pager(render_report(data, fmt, verbose=verbose, color=color))
    return path


__all__ = [
    "REPORT_FORMATS",
    "default_report_path",
    "emit_report",
    "render_report",
    "resolve_report_path",
    "save_report",
]
