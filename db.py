from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class ThreatDB(ABC):
    """
    abstract interface for ti storage backends
    methods operate on plain dicts, without ORM objects leak out

    implementations in:
        SimpleThreatDBAdapter, ThreatIntelligenceORMAdapter,
        InMemoryThreatDB (already with correct interface)
    """

    @abstractmethod
    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        """Add or update a vulnerability. Returns internal integer id."""

    @abstractmethod
    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single vulnerability as a dict, or None."""

    @abstractmethod
    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch vulnerability + all related data (exploits, KEV, runs)."""

    @abstractmethod
    def add_exploit(
        self, cve_id: str, exploit_data: Dict[str, Any]
    ) -> None: ...

    @abstractmethod
    def add_cisa_kev(
        self, cve_id: str, kev_data: Dict[str, Any]
    ) -> None: ...

    @abstractmethod
    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> None: ...

    @abstractmethod
    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str | None = None
    ) -> None: ...

    @abstractmethod
    def search(
        self,
        min_cvss: float | int | None = None,
        severity: str | None = None,
        has_exploit: bool | None = None,
        in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_with_exploits(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_cisa_kev_list(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]: ...

    @abstractmethod
    def add_security_recommendation(
        self, rec_data: Dict[str, Any]
    ) -> int: ...

    @abstractmethod
    def bulk_insert_recommendations(
        self, recommendations: List[Dict[str, Any]]
    ) -> int: ...

    @abstractmethod
    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None,
        limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_recommendations_stats(self) -> Dict[str, Any]: ...

    @abstractmethod
    def bulk_insert(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> int: ...

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class SimpleThreatDBAdapter(ThreatDB):
    """
    Wraps SimpleThreatDB (db_pr.py) behind ThreatDB interface
    Public API methods accept cve_id strings
    Internal methods use integer vuln_id
    """

    def __init__(self, db_path):
        from db_pr import SimpleThreatDB
        self._db = SimpleThreatDB(db_path)

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        return self._db.upsert_vulnerability(data)

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._db.get_vulnerability(cve_id)

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        return self._db.get_vulnerability_with_details(cve_id)

    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> None:
        self._db.add_exploit(cve_id, exploit_data)

    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> None:
        self._db.add_cisa_kev(cve_id, kev_data)

    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> None:
        self._db.add_sandbox_run(cve_id, sandbox_data)

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        return self._db.get_sandbox_runs(cve_id)

    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        self._db.add_reference(cve_id, url, ref_type, source)

    def search(
        self, min_cvss: float | int | None = None, severity: str | None = None,
        has_exploit: bool | None = None, in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return self._db.search(
            min_cvss=min_cvss, severity=severity,
            has_exploit=has_exploit, in_cisa_kev=in_cisa_kev,
            min_criticality=min_criticality,
            limit=limit, offset=offset,
        )

    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._db.get_critical(limit)

    def get_with_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._db.get_with_exploits(limit)

    def get_cisa_kev_list(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._db.get_cisa_kev_list(limit)

    def get_statistics(self) -> Dict[str, Any]:
        return self._db.get_statistics()

    def add_security_recommendation(
        self, rec_data: Dict[str, Any]
    ) -> int:
        return self._db.add_security_recommendation(rec_data)

    def bulk_insert_recommendations(
        self, recommendations: List[Dict[str, Any]]
    ) -> int:
        return self._db.bulk_insert_recommendations(recommendations)

    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None,
        limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        return self._db.get_security_recommendations(
            category=category, status=status,
            limit=limit, offset=offset
        )

    def get_recommendations_stats(self) -> Dict[str, Any]:
        return self._db.get_recommendations_stats()

    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        return self._db.bulk_insert(vulnerabilities)

    def close(self) -> None:
        self._db.close()


class ThreatIntelligenceORMAdapter(ThreatDB):
    """Wraps ThreatIntelligenceORM (db_orm.py) behind ThreatDB.
    ORM uses cve_id strings in add_* methods
    but upsert returns an ORM object, then normalise it to int here."""

    def __init__(self, db_url: str):
        from db_orm import ThreatIntelligenceORM
        self._db = ThreatIntelligenceORM(db_url)

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        vuln = self._db.upsert_vulnerability(data)
        return vuln.id

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vuln = self._db.get_vulnerability(cve_id)
        return vuln.to_dict() if vuln else None

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        return self._db.get_vulnerability_with_details(cve_id)

    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> None:
        self._db.add_exploit(cve_id, exploit_data)

    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> None:
        self._db.add_cisa_kev(cve_id, kev_data)

    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> None:
        self._db.add_sandbox_run(cve_id, sandbox_data)

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        return self._db.get_sandbox_runs(cve_id)

    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str | None = None
    ) -> None:
        self._db.add_reference(cve_id, url, ref_type, source)

    def search(
        self, min_cvss: float | int | None = None, severity: str | None = None,
        has_exploit: bool | None = None, in_cisa_kev: bool | None = None,
        min_criticality: int | None = None,
        limit: int = 100, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return self._db.search(
            min_cvss=min_cvss, severity=severity,
            has_exploit=has_exploit, in_cisa_kev=in_cisa_kev,
            min_criticality=min_criticality,
            limit=limit, offset=offset,
        )

    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._db.get_critical(limit)

    def get_with_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._db.get_with_exploits(limit)

    def get_cisa_kev_list(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._db.get_cisa_kev_list(limit)

    def get_statistics(self) -> Dict[str, Any]:
        return self._db.get_statistics()

    def add_security_recommendation(
        self, rec_data: Dict[str, Any]
    ) -> int:
        return self._db.add_security_recommendation(rec_data)

    def bulk_insert_recommendations(
        self, recommendations: List[Dict[str, Any]]
    ) -> int:
        return self._db.bulk_insert_recommendations(recommendations)

    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None,
        limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        return self._db.get_security_recommendations(
            category=category, status=status,
            limit=limit, offset=offset
        )

    def get_recommendations_stats(self) -> Dict[str, Any]:
        return self._db.get_recommendations_stats()

    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        return self._db.bulk_insert(vulnerabilities)

    def close(self) -> None:
        self._db.close()


def get_db(backend: str = "simple") -> ThreatDB:
    """
    Create a ThreatDB instance for the requested backend.
    backend:
        "simple" — SQLite via db_pr.SimpleThreatDB, kwargs: db_path
        "orm"    — SQLAlchemy via db_orm.ThreatIntelligenceORM, kwargs: db_url
        "memory" — in-memory via db_rd.InMemoryThreatDB, kwargs: none
    """
    if backend == "simple":
        return SimpleThreatDBAdapter(db_path="ti.db")  # different for report
    elif backend == "orm":
        return ThreatIntelligenceORMAdapter(db_url="sqlite:///ti.db")
    elif backend == "memory":
        from db_rd import InMemoryThreatDB
        return InMemoryThreatDB()
    else:
        raise ValueError(
            f"Unknown backend: {backend!r}. Use 'simple', 'orm', or 'memory'.")
