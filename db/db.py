from abc import ABC, abstractmethod

from core.entities import (
    CisaKevEntry,
    Exploit,
    HostInfo,
    RecommendationStats,
    SandboxRun,
    SecurityRecommendation,
    Statistics,
    Vulnerability,
    VulnerabilityDetail,
)


class ThreatDB(ABC):
    """
    abstract interface for ti storage backends
    methods operate on core domain entities"""

    @abstractmethod
    def upsert_vulnerability(self, data: Vulnerability) -> int:
        """Add or update a vulnerability. Returns internal integer id."""

    @abstractmethod
    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        """Fetch a single vulnerability, or None."""

    @abstractmethod
    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> VulnerabilityDetail | None:
        """Fetch vulnerability + all related data (exploits, KEV, runs)."""

    @abstractmethod
    def add_exploit(self, cve_id: str, exploit_data: Exploit) -> None: ...

    @abstractmethod
    def add_cisa_kev(self, cve_id: str, kev_data: CisaKevEntry) -> None: ...

    @abstractmethod
    def add_sandbox_run(self, cve_id: str, sandbox_data: SandboxRun) -> None: ...

    @abstractmethod
    def get_sandbox_runs(self, cve_id: str) -> list[SandboxRun]: ...

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
        vendor: str | None = None,
        product: str | None = None,
        package_ecosystem: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Vulnerability]: ...

    @abstractmethod
    def get_critical(self, limit: int = 50) -> list[Vulnerability]: ...

    @abstractmethod
    def get_with_exploits(self, limit: int = 100) -> list[Vulnerability]: ...

    @abstractmethod
    def get_cisa_kev_list(self, limit: int = 100) -> list[Vulnerability]: ...

    @abstractmethod
    def get_statistics(self) -> Statistics: ...

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
    ) -> list[SecurityRecommendation]: ...

    @abstractmethod
    def get_recommendations_stats(self) -> RecommendationStats: ...

    @abstractmethod
    def add_host_info(self, host: HostInfo) -> int:
        """Persist a host snapshot; returns the host_info row id."""
        ...

    @abstractmethod
    def get_host_info(self, host_info_id: int) -> HostInfo | None: ...

    @abstractmethod
    def get_latest_host_info(self) -> HostInfo | None: ...

    @abstractmethod
    def get_host_infos(self, limit: int = 100, offset: int = 0) -> list[HostInfo]:
        """List host snapshots (header-only: scalar fields, no children)."""
        ...

    @abstractmethod
    def bulk_insert(self, vulnerabilities: list[Vulnerability]) -> int: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def get_db(backend: str = "orm") -> ThreatDB:
    """
    Create a ThreatDB instance for the requested backend.
    backend:
        "orm"    - SQLAlchemy via db_orm.ThreatIntelligenceORM, kwargs: db_url
        "memory" - in-memory via db_rd.InMemoryThreatDB, kwargs: none
    """
    if backend == "orm":
        from db.db_orm import ThreatIntelligenceORM

        return ThreatIntelligenceORM(db_url="sqlite:///ti.db")
    elif backend == "memory":
        from db.db_rd import InMemoryThreatDB

        return InMemoryThreatDB()
    else:
        raise ValueError(
            f"Unknown backend: {backend!r}. Use 'orm' or 'memory'."
        )