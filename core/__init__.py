"""The domain kernel of KernelVulnAuditP.

Public surface of the core package: domain entities plus the parsing and
scoring rules that implement the vulnerability-audit domain. This package is
stdlib-only and depends on nothing else in the project; every other layer
depends on it.
"""

from core.entities import (
    CveExecution,
    CVEFinding,
    ExecutionReport,
    GitHubPoC,
    HostBootParameter,
    HostCgroup,
    HostEnvironmentVariable,
    HostFile,
    HostFileCapabilities,
    HostGroup,
    HostKernelHardening,
    HostKernelModule,
    HostKernelParameter,
    HostNamespace,
    HostProcess,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    HostUser,
    KernelInfo,
    KernelLPE,
    PocExecution,
    RunLogs,
    SandboxRunResult,
    SecurityRecommendationType,
    VmResources,
)
from core.parsing import (
    CVE_RE,
    extract_cve_ids,
    extract_cvss,
    extract_english_description,
    filter_items_by_date,
    norm_sysctl_value,
    parse_date_string,
)
from core.scoring import calculate_criticality_score

__all__ = [
    "CVE_RE",
    "CVEFinding",
    "CveExecution",
    "ExecutionReport",
    "GitHubPoC",
    "HostBootParameter",
    "HostCgroup",
    "HostEnvironmentVariable",
    "HostFile",
    "HostFileCapabilities",
    "HostGroup",
    "HostKernelHardening",
    "HostKernelModule",
    "HostKernelParameter",
    "HostNamespace",
    "HostProcess",
    "HostProcessCapabilities",
    "HostSELinuxBoolean",
    "HostUser",
    "KernelInfo",
    "KernelLPE",
    "PocExecution",
    "RunLogs",
    "SandboxRunResult",
    "SecurityRecommendationType",
    "VmResources",
    "calculate_criticality_score",
    "extract_cve_ids",
    "extract_cvss",
    "extract_english_description",
    "filter_items_by_date",
    "norm_sysctl_value",
    "parse_date_string",
]