from gui.shared.colors import COLOR, SEVERITY_COLORS
from gui.shared.errors import AppError
from gui.shared.formatting import (
    audit_priority,
    binary_output,
    dedupe_links,
    first_resource_line,
    format_kernel_line,
    format_run_timestamp,
    is_url,
    markup_escape,
    rec_context_rows,
    rec_links,
    rec_severity,
    short_hash,
    status_rank,
    suggestion_for,
)
from gui.shared.highlighting import (
    LIST_RULES,
    colorize_line,
    is_header_line,
    matched_ranges,
)

__all__ = [
    "COLOR",
    "LIST_RULES",
    "SEVERITY_COLORS",
    "AppError",
    "audit_priority",
    "binary_output",
    "colorize_line",
    "dedupe_links",
    "first_resource_line",
    "format_kernel_line",
    "format_run_timestamp",
    "is_header_line",
    "is_url",
    "markup_escape",
    "matched_ranges",
    "rec_context_rows",
    "rec_links",
    "rec_severity",
    "short_hash",
    "status_rank",
    "suggestion_for",
]