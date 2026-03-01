CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" \
               "known_exploited_vulnerabilities_schema.json"

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={q}%20&type=repositories"
GITHUB_API_URL = "https://api.github.com/search/repositories?q={q}+language:c&sort=stars&order=desc"
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:linux:linux_kernel:{version}:*"
OSV_API_URL = "https://api.osv.dev/v1/query"
CH_API_URL = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/ChangeLog-{version}"

REQUIREMENTS_RE = r'(?:requirements?|prerequisites?|dependencies|kernel version|affected versions?)[\s:]+([^\n#]+(?:\n(?!#)[^\n]+)*)'
VERSIONS_RE = r'(?:tested on|works on|vulnerable)[\s:]+([^\n#]+)'

LYNIS_BINARY = "lynis"
LYNIS_REPORT_FILE = "/tmp/lynis-report.dat"
LYNIS_LOG_FILE = "/tmp/lynis.log"
LINPEAS_OUT_JSON = "/tmp/linpeas_report.json"
# check here https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS/builder
PATH_LINPEAS = "/tmp/linpeas_kernel.sh"
