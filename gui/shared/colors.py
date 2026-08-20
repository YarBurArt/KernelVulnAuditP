"""Color palette and severity style helpers shared by the TUI widgets."""

from presentation.colors import CRIT_HEX, INFO_HEX, OK_HEX, WARN_HEX

COLOR = {
    "name": "#7ee787",  # no warnings
    "badge": "#79c0ff",  # PIDs, sizes
    "addr": "#ffa657",  # module live address
    "flag": "#ff7b72",  # rwx keys
    "dim": "#8b949e",  # dirs/headers
    "path": "#d2a8ff",  # caps file paths
    "link": "#ffd7b3",  # link targets
}

CRIT = CRIT_HEX
WARN = WARN_HEX
CVE = "#ff5f5f"
RUNS = OK_HEX
OK = OK_HEX
INFO = INFO_HEX

SEVERITY_COLORS = {
    "CRIT": CRIT,
    "CRASH": CRIT,
    "FAIL": CRIT,
    "WARN": WARN,
    "WARNING": WARN,
    "OK": OK,
    "INFO": INFO,
}