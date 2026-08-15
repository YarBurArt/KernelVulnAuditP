"""TUI-only formatting helpers, other in core since same as report"""

from typing import Any

from core import (
    audit_priority,
    binary_output,
    dedupe_links,
    extract_links,
    first_resource_line,
    format_kernel_line,
    format_run_timestamp,
    is_url,
    rec_context_rows,
    rec_severity,
    short_hash,
    status_rank,
    suggestion_for,
)

__all__ = [
    "audit_priority",
    "binary_output",
    "dedupe_links",
    "extract_links",
    "first_resource_line",
    "format_kernel_line",
    "format_run_timestamp",
    "is_url",
    "markup_escape",
    "rec_context_rows",
    "rec_severity",
    "short_hash",
    "status_rank",
    "suggestion_for",
]


def markup_escape(text: Any) -> str:
    """Escape [ so Textual markup can't interpret user text as tags"""
    return str(text).replace("[", r"\[")
