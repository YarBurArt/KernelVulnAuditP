"""Color palette and severity style helpers shared by the TUI widgets"""

COLOR = {
    "name": "#7ee787",  # no warnings
    "badge": "#79c0ff",  # PIDs, sizes
    "addr": "#ffa657",  # module live address
    "flag": "#ff7b72",  # rwx keys
    "dim": "#8b949e",  # dirs/headers
    "path": "#d2a8ff",  # caps file paths
    "link": "#ffd7b3",  # link targets
}

CRIT = "#e01b24"
WARN = "#ff7800"
CVE = "#ff5f5f"
RUNS = "#2ec27e"
OK = "#2ec27e"
INFO = "#8b949e"

SEVERITY_COLORS = {
    "CRIT": CRIT,
    "CRASH": CRIT,
    "FAIL": CRIT,
    "WARN": WARN,
    "WARNING": WARN,
    "OK": OK,
    "INFO": INFO,
}