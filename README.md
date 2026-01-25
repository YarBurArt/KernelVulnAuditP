# KernelVulnAuditP

This is a lightweight, Python-based utility that analyzes Linux systems by reading uname and /proc to accurately determine the running kernel version and configuration details.

The tool automatically queries vulnerability databases, such as CISA KEV, CVE Details and cve.org, scrapes and parses CVE entries, and correlates findings to the exact kernel release.

Results are filtered to highlight kernel-related CVEs and prioritize those with known exploits or public disclosures.

The tool performs automated checks to verify the presence of public exploit code or proof-of-concept repositories, aggregates relevant links, and maps vulnerabilities to their CWE classifications.

The output includes a comprehensive, machine-readable JSON report and a user-friendly HTML report with direct links to advisories, exploit sources, CVE pages, and CWE references, making it easy for administrators to assess real risk and plan remediation.
