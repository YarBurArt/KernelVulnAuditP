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
        ref_type: str = "OTHER", source: str = None
    ) -> None: ...

    @abstractmethod
    def search(
        self,
        min_cvss: float = None,
        severity: str = None,
        has_exploit: bool = None,
        in_cisa_kev: bool = None,
        min_criticality: int = None,
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
    """Wraps SimpleThreatDB (db_pr.py) behind ThreatDB.
    db_pr uses integer vulnerability_id in add_* methods,
    so we resolve cve_id -> int before delegating."""

    def __init__(self, db_path: str = "threat_intel_simple.db"):
        from db_pr import SimpleThreatDB
        self._db = SimpleThreatDB(db_path)

    def _resolve_id(self, cve_id: str) -> int:
        """resolve cve_id to internal integer id"""
        vuln = self._db.get_vulnerability(cve_id)
        if vuln is None:
            raise ValueError(f"Vulnerability {cve_id} not found")
        return vuln['id']

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        return self._db.upsert_vulnerability(data)

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self._db.get_vulnerability(cve_id)

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        return self._db.get_vulnerability_with_details(cve_id)

    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> None:
        self._db.add_exploit(self._resolve_id(cve_id), exploit_data)

    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> None:
        self._db.add_cisa_kev(self._resolve_id(cve_id), kev_data)

    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> None:
        self._db.add_sandbox_run(self._resolve_id(cve_id), sandbox_data)

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        return self._db.get_sandbox_runs(cve_id)

    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str = None
    ) -> None:
        self._db.add_reference(self._resolve_id(cve_id), url, ref_type, source)

    def search(
        self, min_cvss: float = None, severity: str = None,
        has_exploit: bool = None, in_cisa_kev: bool = None,
        min_criticality: int = None,
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

    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        return self._db.bulk_insert(vulnerabilities)

    def close(self) -> None:
        self._db.close()


class ThreatIntelligenceORMAdapter(ThreatDB):
    """Wraps ThreatIntelligenceORM (db_orm.py) behind ThreatDB.
    ORM uses cve_id strings in add_* methods
    but upsert returns an ORM object, then normalise it to int here."""

    def __init__(self, db_url: str = "sqlite:///ti.db"):
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
        ref_type: str = "OTHER", source: str = None
    ) -> None:
        self._db.add_reference(cve_id, url, ref_type, source)

    def search(
        self, min_cvss: float = None, severity: str = None,
        has_exploit: bool = None, in_cisa_kev: bool = None,
        min_criticality: int = None,
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

    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        return self._db.bulk_insert(vulnerabilities)

    def close(self) -> None:
        self._db.close()


def get_db(backend: str = "simple", **kwargs) -> ThreatDB:
    """
    Create a ThreatDB instance for the requested backend.
    backend:
        "simple" — SQLite via db_pr.SimpleThreatDB, kwargs: db_path
        "orm"    — SQLAlchemy via db_orm.ThreatIntelligenceORM, kwargs: db_url
        "memory" — in-memory via db_rd.InMemoryThreatDB, kwargs: none
    """
    if backend == "simple":
        return SimpleThreatDBAdapter(**kwargs)
    elif backend == "orm":
        return ThreatIntelligenceORMAdapter(**kwargs)
    elif backend == "memory":
        from db_rd import InMemoryThreatDB
        return InMemoryThreatDB(**kwargs)
    else:
        raise ValueError(
            f"Unknown backend: {backend!r}. Use 'simple', 'orm', or 'memory'.")


if __name__ == "__main__":
    from db_rd import InMemoryThreatDB

    passed = 0
    failed = 0

    def check(label, condition):
        global passed, failed
        if condition:
            print(f"  \033[92mok\033[0m  {label}")
            passed += 1
        else:
            print(f"  \033[91mFAIL\033[0m {label}")
            failed += 1

    print("running interface smoke tests (memory backend)...")

    # factory produces correct types
    db = get_db("memory")
    # check by MRO name to avoid import identity mismatch when
    # running this file directly (db.py == __main__, db_rd imports db as
    # a separate module, so their ThreatDB objects differ)
    mro_names = [c.__name__ for c in type(db).__mro__]
    check("get_db returns ThreatDB subclass", "ThreatDB" in mro_names)
    check("get_db returns InMemoryThreatDB", isinstance(db, InMemoryThreatDB))

    # for any unknown backend raises
    try:
        get_db("unknown")
        check("unknown backend raises ValueError", False)
    except ValueError:
        check("unknown backend raises ValueError", True)

    # upsert returns int id
    vid = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-0001',
        'description': 'Test RCE',
        'cvss_v3_score': 9.8,
        'severity': 'CRITICAL',
        'sources': ['NIST_NVD'],
    })
    check("upsert returns int", isinstance(vid, int))

    # same cve_id returns same id (update path)
    vid2 = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-0001',
        'description': 'Updated description',
        'cvss_v3_score': 9.8,
        'severity': 'CRITICAL',
    })
    check("upsert update keeps same id", vid == vid2)

    # get_vulnerability round-trip
    vuln = db.get_vulnerability('CVE-2024-0001')
    check("get_vulnerability not None", vuln is not None)
    check(
        "get_vulnerability cve_id matches",
        vuln['cve_id'] == 'CVE-2024-0001'
    )
    check(
        "get_vulnerability description updated",
        vuln['description'] == 'Updated description'
    )
    check("get_vulnerability missing returns None",
          db.get_vulnerability('CVE-9999-9999') is None)

    # add_exploit updates flags
    db.add_exploit('CVE-2024-0001', {
        'exploit_type': 'POC', 'source': 'GitHub',
        'url': 'https://github.com/user/poc', 'verified': True,
    })
    vuln = db.get_vulnerability('CVE-2024-0001')
    check("add_exploit sets has_exploit", vuln['has_exploit'] is True)
    check(
        "add_exploit increments exploit_count",
        vuln['exploit_count'] == 1
    )

    # add_cisa_kev updates flags
    db.add_cisa_kev('CVE-2024-0001', {
        'date_added': '2024-01-20',
        'required_action': 'Patch now',
        'known_ransomware': True,
    })
    vuln = db.get_vulnerability('CVE-2024-0001')
    check("add_cisa_kev sets in_cisa_kev", vuln['in_cisa_kev'] is True)
    check("criticality_score > 60 after kev+exploit+cvss",
          vuln['criticality_score'] > 60)

    # sandbox run round-trip
    db.add_sandbox_run('CVE-2024-0001', {
        'run_timestamp': '2024-01-21T10:30:00',
        'sandbox_platform': 'virtme-ng',
        'exploit_file_hash': 'aabbcc',
        'execution_success': True, 'exit_code': 0,
        'stdout': 'Got shell\n', 'stderr': '', 'stdin': './xpl\n',
        'open_processes': ['/bin/sh'], 'open_files': ['/etc/passwd'],
        'notes': 'LPE confirmed',
    })
    runs = db.get_sandbox_runs('CVE-2024-0001')
    check("get_sandbox_runs returns 1 entry", len(runs) == 1)
    check(
        "sandbox platform stored",
        runs[0]['sandbox_platform'] == 'virtme-ng'
    )

    # get_vulnerability_with_details includes all related data
    full = db.get_vulnerability_with_details('CVE-2024-0001')
    check("details has exploits", len(full['exploits']) == 1)
    check("details has cisa_kev", full['cisa_kev'] is not None)
    check("details has sandbox_runs", len(full['sandbox_runs']) == 1)

    # second vuln for search/stats
    db.upsert_vulnerability({
        'cve_id': 'CVE-2024-0002',
        'description': 'Low severity info leak',
        'cvss_v3_score': 3.1,
        'severity': 'LOW',
        'sources': ['OSV'],
    })

    check("search by severity CRITICAL returns 1",
          len(db.search(severity='CRITICAL')) == 1)
    check("search min_cvss=9.0 returns 1",
          len(db.search(min_cvss=9.0)) == 1)
    check("get_critical returns 1", len(db.get_critical()) == 1)
    check(
        "get_with_exploits returns 1",
        len(db.get_with_exploits()) == 1
    )
    check(
        "get_cisa_kev_list returns 1",
        len(db.get_cisa_kev_list()) == 1
    )

    # bulk_insert
    inserted = db.bulk_insert([
        {
            'cve_id': 'CVE-2024-0010',
            'cvss_v3_score': 7.5, 'severity': 'HIGH'},
        {
            'cve_id': 'CVE-2024-0011',
            'cvss_v3_score': 6.0, 'severity': 'MEDIUM'},
    ])
    check("bulk_insert returns count", inserted == 2)

    stats = db.get_statistics()
    check("stats total == 4", stats['total'] == 4)
    check("stats with_exploits == 1", stats['with_exploits'] == 1)
    check("stats in_cisa_kev == 1", stats['in_cisa_kev'] == 1)
    check(
        "stats ransomware_related == 1",
        stats['ransomware_related'] == 1
    )
    check("stats avg_cvss > 0", stats['avg_cvss'] > 0)

    # context manager closes cleanly
    with get_db("memory") as tmp:
        tmp.upsert_vulnerability(
            {
                'cve_id': 'CVE-2024-9999',
                'cvss_v3_score': 5.0
            }
        )
    check("context manager __exit__ ok", True)

    db.close()
    print(f"\n{passed} passed, {failed} failed")
