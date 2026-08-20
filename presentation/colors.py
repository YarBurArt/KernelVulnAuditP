"""Color palettes for the CLI, TUI, and Streamlit report renderers.

Single source for severity -> color so the renderers do not each re-map the
same severity labels. Three palettes live here because the renderers emit to
different targets (ANSI escapes, hex for Textual styles, CSS like for Streamlit).
"""

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GRAY = "\033[90m"

# used by the audit/report output
CRIT = RED
WARN = YELLOW
OK = GREEN
INFO = CYAN

#: severity class -> ANSI color
_SEV_CLASS_ANSI = {
    "CRIT": CRIT,
    "WARN": WARN,
    "OK": OK,
    "INFO": GRAY,
}

#: severity label -> ANSI color (union of the old report/cli + cli_app maps)
_SEV_TEXT_ANSI = {
    "CRIT": CRIT,
    "CRITICAL": CRIT,
    "HIGH": CRIT,
    "FAIL": CRIT,
    "CRASH": CRIT,
    "MAYBE": WARN,
    "WARN": WARN,
    "WARNING": WARN,
    "MEDIUM": WARN,
    "OK": OK,
    "SUCCESS": OK,
    "LOW": OK,
    "INFO": INFO,
    "UNKNOWN": GRAY,
    "N/A": GRAY,
}

# hex palette for the Textual TUI (from the old gui/shared/colors.py)
CRIT_HEX = "#e01b24"
WARN_HEX = "#ff7800"
OK_HEX = "#2ec27e"
INFO_HEX = "#8b949e"

_SEV_CLASS_HEX = {
    "CRIT": CRIT_HEX,
    "CRASH": CRIT_HEX,
    "FAIL": CRIT_HEX,
    "WARN": WARN_HEX,
    "WARNING": WARN_HEX,
    "OK": OK_HEX,
    "INFO": INFO_HEX,
}

# CSS colors for the Streamlit report renderer
CSS_CRIT = "#b00020"
CSS_WARN = "#b26a00"
CSS_OK = "#1b7a3d"
CSS_INFO = "inherit"

_SEV_CLASS_CSS = {
    "CRIT": CSS_CRIT,
    "WARN": CSS_WARN,
    "OK": CSS_OK,
    "INFO": CSS_INFO,
}


def sev_class_color(sev_class: str) -> str:
    """ANSI color for a severity class (CRIT/WARN/OK/INFO)."""
    return _SEV_CLASS_ANSI.get(sev_class, GRAY)


def sev_text_color(sev: str) -> str:
    """ANSI color for a raw severity label (case-insensitive).

    Unknown labels stay uncolored (empty string), mirroring the old per
    renderer maps which only colored known severities.
    """
    return _SEV_TEXT_ANSI.get(str(sev or "").upper(), "")


def hex_sev_class_color(sev_class: str) -> str:
    """Hex color for a severity class used by the TUI styles."""
    return _SEV_CLASS_HEX.get(sev_class, INFO_HEX)


def css_sev_class_color(sev_class: str) -> str:
    """CSS color for a severity class used by the Streamlit renderer."""
    return _SEV_CLASS_CSS.get(sev_class, CSS_INFO)