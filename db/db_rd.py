import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict, cast

from core import calculate_criticality_score
from db import ThreatDB
from db.models import SecurityRecommendation

logger = logging.getLogger(f"kernel_audit.{__name__}")


class ExploitDict(TypedDict, total=False):
    id: int
    vulnerability_id: str
    exploit_type: str | None
    source: str | None
    url: str | None
    verified: bool
    date_published: str | None


class ReferenceDict(TypedDict):
    id: int
    vulnerability_id: int
    url: str
    ref_type: str | None
    source: str | None


class CISAKEVDict(TypedDict, total=False):
    id: int
    vulnerability_id: int
    date_added: str | None
    due_date: str | None
    required_action: str | None
    known_ransomware: bool
    notes: str | None
    vendor_project: str | None
    product: str | None


class SandboxRunDict(TypedDict, total=False):
    id: int
    vulnerability_id: int
    run_timestamp: str | None
    sandbox_platform: str | None
    exploit_file_hash: str | None
    execution_success: bool
    exit_code: int | None
    crashed: bool
    stdout: str | None
    stderr: str | None
    stdin: str | None
    open_processes: Any
    open_files: Any
    modules: Any
    kernel_info: Any
    resources: Any
    notes: str | None


class VulnerabilityBase(TypedDict):
    id: int
    cve_id: str


class VulnerabilityDict(VulnerabilityBase, total=False):
    description: str | None
    published_date: str | None
    last_modified_date: str | None
    cvss_v2_score: float | None
    cvss_v3_score: float | None
    cvss_v3_vector: str | None
    severity: str | None
    cwe_ids: list[str]
    in_cisa_kev: bool
    has_exploit: bool
    exploit_count: int
    github_refs: int
    exploitdb_refs: int
    sources: list[str]
    raw_data: dict[str, Any]
    criticality_score: int
    created_at: str
    updated_at: str
    known_ransomware: bool
    exploits: list[ExploitDict]
    references: list[ReferenceDict]
    cisa_kev: CISAKEVDict | None
    sandbox_runs: list[SandboxRunDict]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryThreatDB(ThreatDB):
    """
    Pure in-memory backend. No deps to redis for now,
    Useful for tests and offline runs.
    """

    def __init__(self) -> None:
        # cve_id -> vuln dict (source of truth)
        self._vulns: Dict[str, VulnerabilityDict] = {}
        # cve_id -> list of dicts
        self._exploits: Dict[str, List[ExploitDict]] = {}
        self._refs: Dict[str, List[ReferenceDict]] = {}
        self._kev: Dict[str, CISAKEVDict] = {}
        self._sandbox: Dict[str, List[SandboxRunDict]] = {}
        self._recommendations: List[SecurityRecommendation] = []
        self._next_id: int = 1

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        cve_id = data["cve_id"]
        now = _utcnow()

        if cve_id in self._vulns:
            vuln: Dict[str, Any] = dict(self._vulns[cve_id])
            vuln.update({k: v for k, v in data.items() if k != "id"})
            vuln["updated_at"] = now
        else:
            vuln = {
                "id": self._next_id,
                "cve_id": cve_id,
                "description": None,
                "published_date": None,
                "last_modified_date": None,
                "cvss_v2_score": None,
                "cvss_v3_score": None,
                "cvss_v3_vector": None,
                "severity": None,
                "cwe_ids": [],
                "in_cisa_kev": False,
                "has_exploit": False,
                "exploit_count": 0,
                "github_refs": 0,
                "exploitdb_refs": 0,
                "sources": [],
                "raw_data": {},
                "criticality_score": 0,
                "created_at": now,
                "updated_at": now,
            }
            vuln.update(data)
            vuln["id"] = self._next_id
            self._next_id += 1

        vuln["criticality_score"] = calculate_criticality_score(vuln)
        self._vulns[cve_id] = cast(VulnerabilityDict, vuln)
        return vuln["id"]

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vuln = self._vulns.get(cve_id)
        return dict(vuln) if vuln else None

    def get_vulnerability_with_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vuln = self.get_vulnerability(cve_id)
        if not vuln:
            return None
        vuln["exploits"] = list(self._exploits.get(cve_id, []))
        vuln["references"] = list(self._refs.get(cve_id, []))
        entry_kev = self._kev.get(cve_id)
        vuln["cisa_kev"] = entry_kev if entry_kev is not None else None
        vuln["sandbox_runs"] = list(self._sandbox.get(cve_id, []))
        return vuln

    def _require(self, cve_id: str) -> VulnerabilityDict:
        """get vuln or raise if not found"""
        vuln = self._vulns.get(cve_id)
        if vuln is None:
            raise ValueError(f"Vulnerability {cve_id} not found")
        return vuln

    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> None:
        vuln = self._require(cve_id)
        entry = dict(exploit_data)
        entry["id"] = len(self._exploits.get(cve_id, [])) + 1
        entry["vulnerability_id"] = cve_id
        self._exploits.setdefault(cve_id, []).append(cast(ExploitDict, entry))

        # keep summary flags in sync
        vuln["has_exploit"] = True
        vuln["exploit_count"] = len(self._exploits[cve_id])
        vuln["criticality_score"] = calculate_criticality_score(dict(vuln))

    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> None:
        vuln = self._require(cve_id)
        entry = dict(kev_data)
        entry["vulnerability_id"] = vuln["id"]
        self._kev[cve_id] = cast(CISAKEVDict, entry)

        vuln["in_cisa_kev"] = True
        if kev_data.get("known_ransomware"):
            vuln["known_ransomware"] = True
        vuln["criticality_score"] = calculate_criticality_score(dict(vuln))

    def add_sandbox_run(self, cve_id: str, sandbox_data: Dict[str, Any]) -> None:
        vuln = self._require(cve_id)
        entry = dict(sandbox_data)
        entry.setdefault("id", len(self._sandbox.get(cve_id, [])) + 1)
        entry["vulnerability_id"] = vuln["id"]
        self._sandbox.setdefault(cve_id, []).append(cast(SandboxRunDict, entry))

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        return [dict(run) for run in self._sandbox.get(cve_id, [])]

    def add_reference(
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        vuln = self._require(cve_id)
        entry = {
            "id": len(self._refs.get(cve_id, [])) + 1,
            "vulnerability_id": vuln["id"],
            "url": url,
            "ref_type": ref_type,
            "source": source,
        }
        self._refs.setdefault(cve_id, []).append(cast(ReferenceDict, entry))

        if ref_type == "GITHUB" or source == "GitHub":
            vuln["github_refs"] = vuln.get("github_refs", 0) + 1
        elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
            vuln["exploitdb_refs"] = vuln.get("exploitdb_refs", 0) + 1
        vuln["criticality_score"] = calculate_criticality_score(dict(vuln))

    def search(
        self,
        min_cvss: float | int | None = None,
        severity: str | None = None,
        has_exploit: bool | None = None,
        in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:

        results = []

        for vuln in self._vulns.values():
            if min_cvss is not None:
                if (vuln.get("cvss_v3_score") or 0) < min_cvss:
                    continue

            if severity is not None:
                if vuln.get("severity") != severity:
                    continue

            if has_exploit is not None:
                if bool(vuln.get("has_exploit")) != has_exploit:
                    continue

            if in_cisa_kev is not None:
                if bool(vuln.get("in_cisa_kev")) != in_cisa_kev:
                    continue

            if min_criticality is not None:
                if (vuln.get("criticality_score") or 0) < min_criticality:
                    continue

            results.append(dict(vuln))

        results.sort(
            key=lambda v: (
                v.get("criticality_score") or 0,
                v.get("cvss_v3_score") or 0,
            ),
            reverse=True,
        )

        return results[offset : offset + limit]

    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.search(min_criticality=60, limit=limit)

    def get_with_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.search(has_exploit=True, limit=limit)

    def get_cisa_kev_list(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.search(in_cisa_kev=True, limit=limit)

    def get_statistics(self) -> Dict[str, Any]:
        vulns = list(self._vulns.values())
        by_severity: Dict[str, int] = {}
        cvss_sum, cvss_count = 0.0, 0

        for v in vulns:
            sev = v.get("severity")
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + 1
            score = v.get("cvss_v3_score")
            if score is not None:
                cvss_sum += score
                cvss_count += 1

        ransomware = sum(1 for k in self._kev.values() if k.get("known_ransomware"))

        return {
            "total": len(vulns),
            "by_severity": by_severity,
            "with_exploits": sum(1 for v in vulns if v.get("has_exploit")),
            "in_cisa_kev": sum(1 for v in vulns if v.get("in_cisa_kev")),
            "ransomware_related": ransomware,
            "critical_count": sum(
                1 for v in vulns if (v.get("criticality_score") or 0) >= 60
            ),
            "avg_cvss": round(cvss_sum / cvss_count, 2) if cvss_count else 0,
        }

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        rec_data.id = len(self._recommendations) + 1
        self._recommendations.append(rec_data)
        return rec_data.id

    def bulk_insert_recommendations(
        self, recommendations: List[SecurityRecommendation]
    ) -> int:
        count = 0
        for rec in recommendations:
            try:
                self.add_security_recommendation(rec)
                count += 1
            except Exception as e:
                logger.warning(f"Error inserting rec {rec.test_id}: {e}")
        return count

    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for rec in self._recommendations:
            if category and rec.category != category:
                continue
            if status and rec.status != status:
                continue
            results.append(rec.to_dict())
        results.sort(
            key=lambda r: (r.get("severity", "") or "", r.get("test_id", "") or ""),
            reverse=True,
        )
        return results[offset : offset + limit]

    def get_recommendations_stats(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {"total": len(self._recommendations)}
        by_category: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for rec in self._recommendations:
            cat = rec.category
            if cat is not None:
                by_category[cat] = by_category.get(cat, 0) + 1
            stat = rec.status
            if stat is not None:
                by_status[stat] = by_status.get(stat, 0) + 1
            sev = rec.severity
            if sev is not None:
                by_severity[sev] = by_severity.get(sev, 0) + 1

        stats["by_category"] = by_category
        stats["by_status"] = by_status
        stats["by_severity"] = by_severity
        return stats

    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        count = 0
        for vuln_data in vulnerabilities:
            try:
                self.upsert_vulnerability(vuln_data)
                count += 1
            except Exception as e:
                print(f"Error inserting {vuln_data.get('cve_id')}: {e}")
        return count

    def close(self) -> None:
        """no-op for in-memory store; data is simply discarded"""
        pass
