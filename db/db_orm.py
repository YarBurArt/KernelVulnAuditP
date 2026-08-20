from __future__ import annotations

import logging

from sqlalchemy import (
    create_engine,
    event,
)
from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool

from core.entities import (
    AffectedProduct,
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
from db.db import ThreatDB
from db.host_info_repo import HostInfoRepository
from db.models import (
    AffectedProduct as AffectedProductRow,
)
from db.models import (
    Base,
)
from db.recommendation_repo import RecommendationRepository
from db.vulnerability_repo import VulnerabilityRepository

logger = logging.getLogger(f"kernel_audit.{__name__}")


class ThreatIntelligenceORM(ThreatDB):
    """SQLAlchemy-backed ThreatDB: owns the engine / session factory and the
    repositories that implement the vulnerability, host and recommendation
    domains. This is the single seam implementation for the orm backend."""

    def __init__(self, db_url: str = "sqlite:///ti.db"):
        self.engine = create_engine(
            db_url,
            connect_args=(
                {"check_same_thread": False} if db_url.startswith("sqlite") else {}
            ),
            poolclass=StaticPool if db_url == "sqlite:///:memory:" else None,
        )

        if db_url.startswith("sqlite"):

            @event.listens_for(self.engine, "connect")
            def _set_sqlite_pragmas(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                    cursor.execute("PRAGMA busy_timeout=5000")
                finally:
                    cursor.close()

        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self.ScopedSession = scoped_session(self.SessionLocal)
        self._vulnerabilities = VulnerabilityRepository(self.SessionLocal)
        self._host_info = HostInfoRepository(self.SessionLocal)
        self._recommendations = RecommendationRepository(self.SessionLocal)
        logger.debug(f"conn setup to TI DB by {db_url}")

    def upsert_vulnerability(self, data: Vulnerability) -> int:
        return self._vulnerabilities.upsert_vulnerability(data)

    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        return self._vulnerabilities.get_vulnerability(cve_id)

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> VulnerabilityDetail | None:
        return self._vulnerabilities.get_vulnerability_with_details(cve_id)

    def add_affected_product(
        self, cve_id: str, product_data: AffectedProduct
    ) -> AffectedProductRow:
        return self._vulnerabilities.add_affected_product(cve_id, product_data)

    def add_reference(
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        self._vulnerabilities.add_reference(cve_id, url, ref_type, source)

    def add_exploit(self, cve_id: str, exploit_data: Exploit) -> None:
        self._vulnerabilities.add_exploit(cve_id, exploit_data)

    def add_cisa_kev(self, cve_id: str, kev_data: CisaKevEntry) -> None:
        self._vulnerabilities.add_cisa_kev(cve_id, kev_data)

    def add_sandbox_run(self, cve_id: str, sandbox_data: SandboxRun) -> None:
        self._vulnerabilities.add_sandbox_run(cve_id, sandbox_data)

    def get_sandbox_runs(self, cve_id: str) -> list[SandboxRun]:
        return self._vulnerabilities.get_sandbox_runs(cve_id)

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
        return self._vulnerabilities.search(
            min_cvss=min_cvss,
            severity=severity,
            has_exploit=has_exploit,
            in_cisa_kev=in_cisa_kev,
            min_criticality=min_criticality,
            vendor=vendor,
            product=product,
            package_ecosystem=package_ecosystem,
            limit=limit,
            offset=offset,
        )

    def get_critical(self, limit: int = 50) -> list[Vulnerability]:
        return self._vulnerabilities.get_critical(limit)

    def get_with_exploits(self, limit: int = 100) -> list[Vulnerability]:
        return self._vulnerabilities.get_with_exploits(limit)

    def get_cisa_kev_list(self, limit: int = 100) -> list[Vulnerability]:
        return self._vulnerabilities.get_cisa_kev_list(limit)

    def get_statistics(self) -> Statistics:
        return self._vulnerabilities.get_statistics()

    def bulk_insert(self, vulnerabilities: list[Vulnerability]) -> int:
        return self._vulnerabilities.bulk_insert(vulnerabilities)

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        return self._recommendations.add_security_recommendation(rec_data)

    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
    ) -> int:
        return self._recommendations.bulk_insert_recommendations(recommendations)

    def get_security_recommendations(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityRecommendation]:
        return self._recommendations.get_security_recommendations(
            category=category, status=status, limit=limit, offset=offset
        )

    def get_recommendations_stats(self) -> RecommendationStats:
        return self._recommendations.get_recommendations_stats()

    def add_host_info(self, host: HostInfo) -> int:
        return self._host_info.add_host_info(host).id

    def get_host_info(self, host_info_id: int) -> HostInfo | None:
        return self._host_info.get_host_info(host_info_id)

    def get_latest_host_info(self) -> HostInfo | None:
        return self._host_info.get_latest_host_info()

    def get_host_infos(self, limit: int = 100, offset: int = 0) -> list[HostInfo]:
        return self._host_info.get_host_infos(limit=limit, offset=offset)

    def close(self):
        self.ScopedSession.remove()
        self.engine.dispose()
        logger.debug("db connection is closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()