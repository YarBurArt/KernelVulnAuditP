"""Shared rendering for the report, TUI, and CLI renderers.

Single home for formatting and terminal helpers so report/, gui/ and
cli_app.py do not reimplement the same rules. Depends only on the domain
(core) and application DTOs; never on the adapters.
"""

from presentation.colors import (
    CRIT,
    DIM,
    GRAY,
    INFO,
    OK,
    WARN,
    css_sev_class_color,
    hex_sev_class_color,
    sev_class_color,
    sev_text_color,
)
from presentation.formatting import (
    audit_priority,
    dedupe_links,
    dict_to_display_rows,
    extract_links,
    first_resource_line,
    format_kernel_line,
    format_run_timestamp,
    format_timestamp,
    is_finding,
    is_ok_status,
    is_url,
    proc_module_name,
    rec_context_rows,
    rec_severity,
    safe_get_attr,
    short_hash,
    status_rank,
    status_severity,
    suggestion_for,
)
from presentation.glyphs import supports_unicode, unicode_glyph
from presentation.sandbox import (
    binary_output,
    format_execution_report,
    format_sandbox_detail,
    log_sandbox_run,
)
from presentation.terminal import (
    ProgressBar,
    is_interactive,
    pager,
    paint,
    supports_color,
)

__all__ = [
    "CRIT",
    "DIM",
    "GRAY",
    "INFO",
    "OK",
    "WARN",
    "ProgressBar",
    "audit_priority",
    "binary_output",
    "css_sev_class_color",
    "dedupe_links",
    "dict_to_display_rows",
    "extract_links",
    "first_resource_line",
    "format_execution_report",
    "format_kernel_line",
    "format_run_timestamp",
    "format_sandbox_detail",
    "format_timestamp",
    "hex_sev_class_color",
    "is_finding",
    "is_interactive",
    "is_ok_status",
    "is_url",
    "log_sandbox_run",
    "pager",
    "paint",
    "proc_module_name",
    "rec_context_rows",
    "rec_severity",
    "safe_get_attr",
    "sev_class_color",
    "sev_text_color",
    "short_hash",
    "status_rank",
    "status_severity",
    "suggestion_for",
    "supports_color",
    "supports_unicode",
    "unicode_glyph",
]