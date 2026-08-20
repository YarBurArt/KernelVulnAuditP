import atexit
import os
import shutil
import tempfile
from pathlib import Path

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={q}%20&type=repositories"
GITHUB_API_URL = (
    "https://api.github.com/search/repositories?q={q}+language:c&sort=stars&order=desc"
)
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:linux:linux_kernel:{version}:*"
NIST_CVE_DETAILS_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
OSV_API_URL = "https://api.osv.dev/v1/query"
CH_API_URL = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/ChangeLog-{version}"

REQUIREMENTS_RE = r"(?:requirements?|prerequisites?|dependencies|kernel version|affected versions?)[\s:]+([^\n#]+(?:\n(?!#)[^\n]+)*)"
VERSIONS_RE = r"(?:tested on|works on|vulnerable)[\s:]+([^\n#]+)"

LYNIS_BINARY = "lynis"


def _make_scratch_dir() -> Path:
    """One private (0o700) scratch dir per process for generated reports.

    lynis/linpeas/les write fixed filenames; a unique, non-world-writable
    directory per process avoids predictable-/tmp symlink races and prevents
    concurrent scans from clobbering each other's reports.
    """
    scratch = Path(tempfile.mkdtemp(prefix="kernauditp-"))
    atexit.register(shutil.rmtree, scratch, ignore_errors=True)
    return scratch


_SCRATCH_DIR = _make_scratch_dir()

LYNIS_REPORT_FILE = str(_SCRATCH_DIR / "lynis-report.dat")
LYNIS_LOG_FILE = str(_SCRATCH_DIR / "lynis.log")
LINPEAS_OUT_JSON = str(_SCRATCH_DIR / "linpeas_report.json")
LINPEAS_REPORT_TXT = str(_SCRATCH_DIR / "linpeas_report.txt")
LES_REPORT_PATH = str(_SCRATCH_DIR / "les_report.txt")

# tool input locations, installed by install_tools.sh into the repo's
# lib_tools/ dir; override here if you keep them elsewhere
# check here https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS/builder
PATH_LINPEAS = "lib_tools/linpeas_kernel.sh"
POCS_BASE_PATH = "lib_tools/pocs"

LES_PATH = "lib_tools/linux-exploit-suggester/linux-exploit-suggester.sh"
DB_BACKEND = "orm"

# full VM boot + PoC run needs more than a few seconds; the VMs also shut
# down cleanly before the guest exits, so the budget is generous.
ISOLATION_TIMEOUT_SEC = 60

# recon subprocess audits (linpeas, les, getsebool, getcap) run unbounded
# filesystem/process walks and can stall for minutes; cap each so the scan
# cannot hang. Raise via --set RECON_TOOL_TIMEOUT_SEC=300 if needed.
RECON_TOOL_TIMEOUT_SEC = 60
# per-step budget for host-side PoC compiles (make/gcc can be slow)
COMPILE_TIMEOUT_SEC = 60
ALLOW_HOST_EXECUTION = False
#   "auto"      - try virtme-ng, then qemu; host only with explicit permission
#   "virtme-ng" - virtme-ng only (host fallback subject to permission)
#   "qemu"      - qemu microvm only (host fallback subject to permission)
#   "host"      - run directly on the host
SANDBOX_BACKEND = os.environ.get("KERNEL_AUDIT_SANDBOX", "auto")
LOG_LEVEL = "DEBUG"
