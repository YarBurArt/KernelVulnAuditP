import copy
import logging
from dataclasses import asdict
from datetime import UTC, datetime

from core.entities import (
    HOST_INFO_CHILD_FIELDS,
    CisaKevEntry,
    Exploit,
    HostInfo,
    RecommendationStats,
    Reference,
    SandboxRun,
    SecurityRecommendation,
    Statistics,
    Vulnerability,
    VulnerabilityDetail,
)
from core.scoring import calculate_criticality_score
from db import ThreatDB
from db.mappers import entity_write_dict

logger = logging.getLogger(f"kernel_audit.{__name__}")


class InMemoryThreatDB(ThreatDB):
    """
    Pure in-memory backend. No deps to redis for now,
    Useful for tests and offline runs.
    """

    def __init__(self) -> None:
        # cve_id -> vuln entity (source of truth)
        self._vulns: dict[str, Vulnerability] = {}
        # cve_id -> list of related entities
        self._exploits: dict[str, list[Exploit]] = {}
        self._refs: dict[str, list[Reference]] = {}
        self._kev: dict[str, CisaKevEntry] = {}
        self._sandbox: dict[str, list[SandboxRun]] = {}
        self._recommendations: list[SecurityRecommendation] = []
        self._host_infos: list[HostInfo] = []
        self._next_host_id: int = 1
        self._next_id: int = 1

    def upsert_vulnerability(self, data: Vulnerability) -> int:
        write = entity_write_dict(data)
        cve_id = write["cve_id"]
        now = datetime.now(UTC)

        if cve_id in self._vulns:
            vuln = self._vulns[cve_id]
            for key, value in write.items():
                if key != "id":
                    setattr(vuln, key, value)
            vuln.updated_at = now
        else:
            vuln = copy.deepcopy(data)
            vuln.id = self._next_id
            self._next_id += 1
            if vuln.created_at is None:
                vuln.created_at = now
            vuln.updated_at = now
            self._vulns[cve_id] = vuln

        vuln.criticality_score = calculate_criticality_score(asdict(vuln))
        assert vuln.id is not None
        return vuln.id

    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        vuln = self._vulns.get(cve_id)
        return copy.deepcopy(vuln) if vuln else None

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> VulnerabilityDetail | None:
        vuln = self.get_vulnerability(cve_id)
        if not vuln:
            return None
        return VulnerabilityDetail(
            **asdict(vuln),
            affected_products=[],
            references=copy.deepcopy(self._refs.get(cve_id, [])),
            exploits=copy.deepcopy(self._exploits.get(cve_id, [])),
            cisa_kev=copy.deepcopy(self._kev.get(cve_id)),
            sandbox_runs=copy.deepcopy(self._sandbox.get(cve_id, [])),
        )

    def _require(self, cve_id: str) -> Vulnerability:
        """get vuln or raise if not found"""
        vuln = self._vulns.get(cve_id)
        if vuln is None:
            raise ValueError(f"Vulnerability {cve_id} not found")
        return vuln

    def add_exploit(self, cve_id: str, exploit_data: Exploit) -> None:
        vuln = self._require(cve_id)
        entry = copy.deepcopy(exploit_data)
        entry.id = len(self._exploits.get(cve_id, [])) + 1
        entry.vulnerability_id = vuln.id
        self._exploits.setdefault(cve_id, []).append(entry)

        # keep summary flags in sync
        vuln.has_exploit = True
        vuln.exploit_count = len(self._exploits[cve_id])
        vuln.criticality_score = calculate_criticality_score(asdict(vuln))

    def add_cisa_kev(self, cve_id: str, kev_data: CisaKevEntry) -> None:
        vuln = self._require(cve_id)
        entry = copy.deepcopy(kev_data)
        entry.vulnerability_id = vuln.id
        self._kev[cve_id] = entry

        vuln.in_cisa_kev = True
        if entry.known_ransomware:
            vuln.known_ransomware = True
        vuln.criticality_score = calculate_criticality_score(asdict(vuln))

    def add_sandbox_run(self, cve_id: str, sandbox_data: SandboxRun) -> None:
        vuln = self._require(cve_id)
        entry = copy.deepcopy(sandbox_data)
        entry.id = len(self._sandbox.get(cve_id, [])) + 1
        entry.vulnerability_id = vuln.id
        self._sandbox.setdefault(cve_id, []).append(entry)

    def get_sandbox_runs(self, cve_id: str) -> list[SandboxRun]:
        return copy.deepcopy(self._sandbox.get(cve_id, []))

    def add_reference(
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        vuln = self._require(cve_id)
        entry = Reference(
            id=len(self._refs.get(cve_id, [])) + 1,
            vulnerability_id=vuln.id,
            url=url,
            ref_type=ref_type,
            source=source,
        )
        self._refs.setdefault(cve_id, []).append(entry)

        if ref_type == "GITHUB" or source == "GitHub":
            vuln.github_refs += 1
        elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
            vuln.exploitdb_refs += 1
        vuln.criticality_score = calculate_criticality_score(asdict(vuln))

    def search(
        self,
        min_cvss: float | None = None,
        severity: str | None = None,
        has_exploit: bool | None = None,
        in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        vendor: str | None = None,
        product: str | None = None,
        package_ecosystem: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Vulnerability]:

        results = []

        for vuln in self._vulns.values():
            if min_cvss is not None and (vuln.cvss_v3_score or 0) < min_cvss:
                continue

            if severity is not None and vuln.severity != severity:
                continue

            if has_exploit is not None and vuln.has_exploit != has_exploit:
                continue

            if in_cisa_kev is not None and vuln.in_cisa_kev != in_cisa_kev:
                continue

            if min_criticality is not None and vuln.criticality_score < min_criticality:
                continue

            results.append(vuln)

        results.sort(
            key=lambda v: (v.criticality_score, v.cvss_v3_score or 0),
            reverse=True,
        )

        return [
            copy.deepcopy(v) for v in results[offset : offset + limit]
        ]

    def get_critical(self, limit: int = 50) -> list[Vulnerability]:
        return self.search(min_criticality=60, limit=limit)

    def get_with_exploits(self, limit: int = 100) -> list[Vulnerability]:
        return self.search(has_exploit=True, limit=limit)

    def get_cisa_kev_list(self, limit: int = 100) -> list[Vulnerability]:
        return self.search(in_cisa_kev=True, limit=limit)

    def get_statistics(self) -> Statistics:
        vulns = list(self._vulns.values())
        by_severity: dict[str, int] = {}
        cvss_sum, cvss_count = 0.0, 0

        for v in vulns:
            sev = v.severity
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + 1
            score = v.cvss_v3_score
            if score is not None:
                cvss_sum += score
                cvss_count += 1

        ransomware = sum(1 for k in self._kev.values() if k.known_ransomware)

        return Statistics(
            total=len(vulns),
            by_severity=by_severity,
            with_exploits=sum(1 for v in vulns if v.has_exploit),
            in_cisa_kev=sum(1 for v in vulns if v.in_cisa_kev),
            ransomware_related=ransomware,
            critical_count=sum(1 for v in vulns if v.criticality_score >= 60),
            avg_cvss=round(cvss_sum / cvss_count, 2) if cvss_count else 0,
        )

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        rec = copy.deepcopy(rec_data)
        rec.id = len(self._recommendations) + 1
        self._recommendations.append(rec)
        return rec.id

    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int:
        count = 0
        for rec in recommendations:
            try:
                self.add_security_recommendation(rec)
                count += 1
            except (TypeError, AttributeError) as e:
                logger.warning(f"Error inserting rec {rec.test_id}: {e}")
        return count

    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityRecommendation]:
        results: list[SecurityRecommendation] = []
        for rec in self._recommendations:
            if category and rec.category != category:
                continue
            if status and rec.status != status:
                continue
            results.append(rec)
        results.sort(
            key=lambda r: ((r.severity or ""), (r.test_id or "")),
            reverse=True,
        )
        return copy.deepcopy(results[offset : offset + limit])

    def get_recommendations_stats(self) -> RecommendationStats:
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}

        for rec in self._recommendations:
            if rec.category is not None:
                by_category[rec.category] = by_category.get(rec.category, 0) + 1
            if rec.status is not None:
                by_status[rec.status] = by_status.get(rec.status, 0) + 1
            if rec.severity is not None:
                by_severity[rec.severity] = by_severity.get(rec.severity, 0) + 1

        return RecommendationStats(
            total=len(self._recommendations),
            by_category=by_category,
            by_status=by_status,
            by_severity=by_severity,
        )

    @staticmethod
    def _host_sort_key(host: HostInfo) -> tuple[float, int]:
        ts = host.captured_at.timestamp() if host.captured_at else 0.0
        return ts, host.id or 0

    @staticmethod
    def _host_header_only(host: HostInfo) -> HostInfo:
        for field_name in HOST_INFO_CHILD_FIELDS:
            setattr(host, field_name, [])
        return host

    def add_host_info(self, host: HostInfo) -> int:
        snapshot = copy.deepcopy(host)
        snapshot.id = self._next_host_id
        self._next_host_id += 1
        now = datetime.now(UTC)
        if snapshot.captured_at is None:
            snapshot.captured_at = now
        if snapshot.created_at is None:
            snapshot.created_at = now
        snapshot.updated_at = now
        self._host_infos.append(snapshot)
        assert snapshot.id is not None
        return snapshot.id

    def get_host_info(self, host_info_id: int) -> HostInfo | None:
        for snapshot in self._host_infos:
            if snapshot.id == host_info_id:
                return copy.deepcopy(snapshot)
        return None

    def get_latest_host_info(self) -> HostInfo | None:
        if not self._host_infos:
            return None
        latest = max(self._host_infos, key=self._host_sort_key)
        return copy.deepcopy(latest)

    def get_host_infos(
        self, limit: int = 100, offset: int = 0
    ) -> list[HostInfo]:
        ordered = sorted(self._host_infos, key=self._host_sort_key, reverse=True)
        return [
            self._host_header_only(copy.deepcopy(snapshot))
            for snapshot in ordered[offset : offset + limit]
        ]

    def bulk_insert(self, vulnerabilities: list[Vulnerability]) -> int:
        count = 0
        for vuln_data in vulnerabilities:
            try:
                self.upsert_vulnerability(vuln_data)
                count += 1
            except (ValueError, KeyError, TypeError, AttributeError) as e:
                cve_id = getattr(vuln_data, "cve_id", None)
                print(f"Error inserting {cve_id}: {e}")
        return count

    def close(self) -> None:
        """no-op for in-memory store; data is simply discarded"""