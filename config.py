CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" \
               "known_exploited_vulnerabilities_schema.json"

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={q}%20&type=repositories"
GITHUB_API_URL = "https://api.github.com/search/repositories?q={q}+language:c&sort=stars&order=desc"
NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:linux:linux_kernel:{version}:*"
OSV_API_URL = "https://api.osv.dev/v1/query"
CH_API_URL = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/ChangeLog-{version}"
