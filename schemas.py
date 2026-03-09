from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class KernelAuditItem:
    test_id: str
    category: str
    desc: str
    field: str
    prefval: str
    value: str


@dataclass
class KernelLPE:
    os: str = ""
    user_groups: str = ""
    hostname: str = ""
    cves: List[str] = field(default_factory=list)


@dataclass
class LesCVEItem:
    cve_id: str = ""
    title: str = ""
    details: str = ""
    exposure: str = ""
    tags: List[str] = field(default_factory=list)
    download_urls: List[str] = field(default_factory=list)
    comments: str = ""


@dataclass
class LocalReconResult:
    kernel: str = ""
    system: str = ""
    build_date: int = 0
    kernel_audit: List[KernelAuditItem] = field(default_factory=list)
    kernel_lpe: KernelLPE = field(default_factory=KernelLPE)
    possible_cves: List[LesCVEItem] = field(default_factory=list)


@dataclass
class FeedsReconResult:
    nist: List[dict] = field(default_factory=list)
    osv: Dict = field(default_factory=dict)
    github: List[dict] = field(default_factory=list)


@dataclass
class ReconResult:
    local: LocalReconResult = field(default_factory=LocalReconResult)
    feeds: FeedsReconResult = field(default_factory=FeedsReconResult)
