from abc import ABC, abstractmethod
from typing import Any

from db.models import SecurityRecommendation
from schemas import HostInfoData


class ThreatDB(ABC):
    """
    abstract interface for ti storage backends
    methods operate on plain dicts, without ORM objects leak out

    implementations in:
        SimpleThreatDBAdapter, ThreatIntelligenceORMAdapter,
        InMemoryThreatDB (already with correct interface)
    """

    @abstractmethod
    def upsert_vulnerability(self, data: dict[str, Any]) -> int:
        """Add or update a vulnerability. Returns internal integer id."""

    @abstractmethod
    def get_vulnerability(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch a single vulnerability as a dict, or None."""

    @abstractmethod
    def get_vulnerability_with_details(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch vulnerability + all related data (exploits, KEV, runs)."""

    @abstractmethod
    def add_exploit(self, cve_id: str, exploit_data: dict[str, Any]) -> None: ...

    @abstractmethod
    def add_cisa_kev(self, cve_id: str, kev_data: dict[str, Any]) -> None: ...

    @abstractmethod
    def add_sandbox_run(self, cve_id: str, sandbox_data: dict[str, Any]) -> None: ...

    @abstractmethod
    def get_sandbox_runs(self, cve_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def add_reference(
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> None: ...

    @abstractmethod
    def search(
        self,
        min_cvss: float | None = None,
        severity: str | None = None,
        has_exploit: bool | None = None,
        in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_critical(self, limit: int = 50) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_with_exploits(self, limit: int = 100) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_cisa_kev_list(self, limit: int = 100) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_statistics(self) -> dict[str, Any]: ...

    @abstractmethod
    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int: ...

    @abstractmethod
    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int: ...

    @abstractmethod
    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_recommendations_stats(self) -> dict[str, Any]: ...

    @abstractmethod
    def add_host_info(self, host: HostInfoData) -> int:
        """Persist a host snapshot; returns the host_info row id."""
        ...

    @abstractmethod
    def get_host_info(self, host_info_id: int) -> HostInfoData | None: ...

    @abstractmethod
    def get_latest_host_info(self) -> HostInfoData | None: ...

    @abstractmethod
    def get_host_infos(
        self, limit: int = 100, offset: int = 0
    ) -> list[HostInfoData]:
        """List host snapshots (header-only: scalar fields, no children)."""
        ...

    @abstractmethod
    def bulk_insert(self, vulnerabilities: list[dict[str, Any]]) -> int: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class ThreatIntelligenceORMAdapter(ThreatDB):
    """Wraps ThreatIntelligenceORM (db_orm.py) behind ThreatDB.
    ORM uses cve_id strings in add_* methods
    but upsert returns an ORM object, then normalize it to int here."""

    def __init__(self, db_url: str):
        from db.db_orm import ThreatIntelligenceORM

        self._db = ThreatIntelligenceORM(db_url)

    def upsert_vulnerability(self, data: dict[str, Any]) -> int:
        vuln = self._db.upsert_vulnerability(data)
        return vuln.id

    def get_vulnerability(self, cve_id: str) -> dict[str, Any] | None:
        vuln = self._db.get_vulnerability(cve_id)
        return vuln.to_dict() if vuln else None

    def get_vulnerability_with_details(self, cve_id: str) -> dict[str, Any] | None:
        return self._db.get_vulnerability_with_details(cve_id)

    def add_exploit(self, cve_id: str, exploit_data: dict[str, Any]) -> None:
        self._db.add_exploit(cve_id, exploit_data)

    def add_cisa_kev(self, cve_id: str, kev_data: dict[str, Any]) -> None:
        self._db.add_cisa_kev(cve_id, kev_data)

    def add_sandbox_run(self, cve_id: str, sandbox_data: dict[str, Any]) -> None:
        self._db.add_sandbox_run(cve_id, sandbox_data)

    def get_sandbox_runs(self, cve_id: str) -> list[dict[str, Any]]:
        return self._db.get_sandbox_runs(cve_id)

    def add_reference(
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        self._db.add_reference(cve_id, url, ref_type, source)

    def search(
        self,
        min_cvss: float | None = None,
        severity: str | None = None,
        has_exploit: bool | None = None,
        in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self._db.search(
            min_cvss=min_cvss,
            severity=severity,
            has_exploit=has_exploit,
            in_cisa_kev=in_cisa_kev,
            min_criticality=min_criticality,
            limit=limit,
            offset=offset,
        )

    def get_critical(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._db.get_critical(limit)

    def get_with_exploits(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._db.get_with_exploits(limit)

    def get_cisa_kev_list(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._db.get_cisa_kev_list(limit)

    def get_statistics(self) -> dict[str, Any]:
        return self._db.get_statistics()

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        return self._db.add_security_recommendation(rec_data)

    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int:
        return self._db.bulk_insert_recommendations(recommendations)

    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self._db.get_security_recommendations(
            category=category, status=status, limit=limit, offset=offset
        )

    def get_recommendations_stats(self) -> dict[str, Any]:
        return self._db.get_recommendations_stats()

    def add_host_info(self, host: HostInfoData) -> int:
        return self._db.add_host_info(host).id

    def get_host_info(self, host_info_id: int) -> HostInfoData | None:
        return self._db.get_host_info(host_info_id)

    def get_latest_host_info(self) -> HostInfoData | None:
        return self._db.get_latest_host_info()

    def get_host_infos(
        self, limit: int = 100, offset: int = 0
    ) -> list[HostInfoData]:
        return self._db.get_host_infos(limit=limit, offset=offset)

    def bulk_insert(self, vulnerabilities: list[dict[str, Any]]) -> int:
        return self._db.bulk_insert(vulnerabilities)

    def close(self) -> None:
        self._db.close()


def get_db(backend: str = "orm") -> ThreatDB:
    """
    Create a ThreatDB instance for the requested backend.
    backend:
        "orm"    — SQLAlchemy via db_orm.ThreatIntelligenceORM, kwargs: db_url
        "memory" — in-memory via db_rd.InMemoryThreatDB, kwargs: none
    """
    if backend == "orm":
        return ThreatIntelligenceORMAdapter(db_url="sqlite:///ti.db")
    elif backend == "memory":
        from db.db_rd import InMemoryThreatDB

        return InMemoryThreatDB()
    else:
        raise ValueError(
            f"Unknown backend: {backend!r}. Use 'simple', 'orm', or 'memory'."
        )
