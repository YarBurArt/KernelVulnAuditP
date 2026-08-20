"""Application transfer objects.

Objects that cross the boundary between adapters (recon, isolate) and the
application services, or between the application and the presentation
layers. Domain entities live in core.entities; anything here is plumbing
for a specific call — never pure domain vocabulary.

The DB backends and their repositories speak core.entities directly.
Their names are re-exported from core.entities for callers that
used the DTO module as a one-stop import site.
"""

from dataclasses import dataclass, field

from core.entities import (
    HOST_INFO_CHILD_FIELDS,
    CisaKevEntry,
    CVEFinding,
    Exploit,
    GitHubPoC,
    HostFileCapabilities,
    HostInfo,
    HostProcessCapabilities,
    HostSELinuxBoolean,
    KernelLPE,
    RecommendationStats,
    SandboxRun,
    SecurityRecommendation,
    SecurityRecommendationType,
    Statistics,
    Vulnerability,
    VulnerabilityDetail,
)

__all__ = [
    "HOST_INFO_CHILD_FIELDS",
    "CisaKevEntry",
    "Exploit",
    "FeedsReconResult",
    "HostInfo",
    "KernelLPE",
    "LesCVEItem",
    "LocalReconResult",
    "RecommendationStats",
    "ReconResult",
    "SandboxRun",
    "SecurityRecommendation",
    "Statistics",
    "Vulnerability",
    "VulnerabilityDetail",
]


@dataclass
class LesCVEItem:
    cve_id: str = ""
    title: str = ""
    details: str = ""
    exposure: str = ""
    tags: list[str] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    comments: str = ""


@dataclass
class LocalReconResult:
    kernel: str = ""
    system: str = ""
    build_date: int = 0
    kernel_lpe: KernelLPE = field(default_factory=KernelLPE)
    possible_cves: list[LesCVEItem] = field(default_factory=list)
    security_recommendations: list[SecurityRecommendationType] = field(
        default_factory=list
    )
    selinux_booleans: list[HostSELinuxBoolean] = field(default_factory=list)
    file_capabilities: list[HostFileCapabilities] = field(default_factory=list)
    process_capabilities: list[HostProcessCapabilities] = field(
        default_factory=list
    )
    selinux_hardening: list[SecurityRecommendationType] = field(
        default_factory=list
    )
    capability_hardening: list[SecurityRecommendationType] = field(
        default_factory=list
    )


@dataclass
class FeedsReconResult:
    findings: list[CVEFinding] = field(default_factory=list)
    pocs: list[GitHubPoC] = field(default_factory=list)


@dataclass
class ReconResult:
    local: LocalReconResult = field(default_factory=LocalReconResult)
    feeds: FeedsReconResult = field(default_factory=FeedsReconResult)