from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class KernelAuditItem:
    """raw lynis audit item (legacy, kept for recon.py compat)"""
    test_id: str
    category: str
    desc: str
    field: str
    prefval: str
    value: str


@dataclass
class SecurityRecommendation:
    """unified security recommendation (from lynis or other sources)"""
    test_id: str = ""
    category: str = ""
    description: str = ""
    field_name: str = ""
    expected_value: str = ""
    actual_value: str = ""
    status: str = ""
    severity: str = ""
    source: str = "lynis"
    raw_data: Dict = field(default_factory=dict)

    @classmethod
    def from_kernel_audit(
        cls, item: KernelAuditItem
    ) -> "SecurityRecommendation":
        """convert KernelAuditItem to SecurityRecommendation"""
        status = "OK"
        severity = "INFO"

        raw = item.raw_data if hasattr(item, 'raw_data') else {}
        warning = raw.get('warning', '')
        suggestion = raw.get('suggestion', '')
        solution = raw.get('solution', '')

        desc = item.desc
        if solution:
            status = "FAIL"
            severity = "HIGH"
            desc = solution
        elif warning or suggestion:
            status = "WARNING"
            severity = "MEDIUM"
            if suggestion and not desc:
                desc = suggestion

        return cls(
            test_id=item.test_id,
            category=item.category,
            description=desc,
            field_name=item.field,
            expected_value=item.prefval,
            actual_value=item.value,
            status=status,
            severity=severity,
            source="lynis",
            raw_data=raw
        )

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "SecurityRecommendation":
        """create from lynis-style dict"""
        item = KernelAuditItem(
            test_id=data.get('test_id', ''),
            category=data.get('category', ''),
            desc=data.get('desc', '') or data.get('description', ''),
            field=data.get('field', ''),
            prefval=data.get('prefval', ''),
            value=data.get('value', '')
        )
        rec = cls.from_kernel_audit(item)
        rec.raw_data.update(data)
        return rec


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
    security_recommendations: List[SecurityRecommendation] = field(
        default_factory=list)


@dataclass
class FeedsReconResult:
    nist: List[dict] = field(default_factory=list)
    osv: Dict = field(default_factory=dict)
    github: List[dict] = field(default_factory=list)


@dataclass
class ReconResult:
    local: LocalReconResult = field(default_factory=LocalReconResult)
    feeds: FeedsReconResult = field(default_factory=FeedsReconResult)
