"""Normalized scan host info snapshots for TUI, consumed by the scan page renderer"""

from __future__ import annotations

from dataclasses import dataclass, field

from gui.shared.formatting import audit_priority, status_rank
from schemas import (
    CVEFinding,
    FeedsReconResult,
    GitHubPoC,
    LesCVEItem,
    LocalReconResult,
    SecurityRecommendationType,
)


@dataclass
class ScanSnapshot:
    """Sorted hardening + CVE data from a local recon run."""

    kernel: str = ""
    system: str = ""
    audit: list[SecurityRecommendationType] = field(default_factory=list)
    selinux: list[SecurityRecommendationType] = field(default_factory=list)
    caps: list[SecurityRecommendationType] = field(default_factory=list)
    cves: list[LesCVEItem] = field(default_factory=list)

    @classmethod
    def from_local(cls, local: LocalReconResult) -> ScanSnapshot:
        return cls(
            kernel=local.kernel,
            system=local.system,
            audit=sorted(local.security_recommendations, key=audit_priority),
            selinux=sorted(local.selinux_hardening, key=status_rank),
            caps=sorted(local.capability_hardening, key=status_rank),
            cves=list(local.possible_cves or []),
        )


@dataclass
class FeedsSnapshot:
    """CVE findings + PoCs from a TI feed run."""

    findings: list[CVEFinding] = field(default_factory=list)
    pocs: list[GitHubPoC] = field(default_factory=list)

    @classmethod
    def from_feeds(cls, feeds: FeedsReconResult) -> FeedsSnapshot:
        return cls(findings=list(feeds.findings or []), pocs=list(feeds.pocs or []))


__all__ = ["FeedsSnapshot", "ScanSnapshot"]