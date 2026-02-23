from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from db import ThreatDB


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calculate_criticality(data: Dict[str, Any]) -> int:
    """criticality score (0-100) — mirrors db_pr logic"""
    score = 0
    if data.get('in_cisa_kev'):
        score += 40
        if data.get('known_ransomware'):
            score += 20
    if data.get('has_exploit'):
        score += 25
        score += min(data.get('exploit_count', 0) * 2, 10)

    cvss = data.get('cvss_v3_score') or data.get('cvss_v2_score') or 0
    score += int(cvss * 2)
    score += min(data.get('github_refs', 0) * 3, 15)
    score += min(data.get('exploitdb_refs', 0) * 3, 15)

    return min(score, 100)


class InMemoryThreatDB(ThreatDB):
    """
    Pure in-memory backend. No deps to redis for now,
    Useful for tests and offline runs.
    """

    def __init__(self):
        # cve_id -> vuln dict (source of truth)
        self._vulns: Dict[str, Dict[str, Any]] = {}
        # cve_id -> list of dicts
        self._exploits: Dict[str, List[Dict[str, Any]]] = {}
        self._refs: Dict[str, List[Dict[str, Any]]] = {}
        self._kev: Dict[str, Dict[str, Any]] = {}
        self._sandbox: Dict[str, List[Dict[str, Any]]] = {}
        self._next_id: int = 1

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        cve_id = data['cve_id']
        now = _utcnow()

        if cve_id in self._vulns:
            vuln = self._vulns[cve_id]
            vuln.update({k: v for k, v in data.items() if k != 'id'})
            vuln['updated_at'] = now
        else:
            vuln = {
                'id': self._next_id,    'cve_id': cve_id, 'description': None,
                'published_date': None, 'last_modified_date': None,
                'cvss_v2_score': None,  'cvss_v3_score': None,
                'cvss_v3_vector': None, 'severity': None, 'cwe_ids': [],
                'in_cisa_kev': False,   'has_exploit': False,
                'exploit_count': 0, 'github_refs': 0, 'exploitdb_refs': 0,
                'sources': [],      'raw_data': {}, 'criticality_score': 0,
                'created_at': now,  'updated_at': now,
            }
            vuln.update(data)
            vuln['id'] = self._next_id  # never let caller overwrite id
            self._vulns[cve_id] = vuln
            self._next_id += 1

        vuln['criticality_score'] = _calculate_criticality(vuln)
        return vuln['id']

    def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        vuln = self._vulns.get(cve_id)
        return dict(vuln) if vuln else None

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        vuln = self.get_vulnerability(cve_id)
        if not vuln:
            return None
        vuln['exploits'] = list(self._exploits.get(cve_id, []))
        vuln['references'] = list(self._refs.get(cve_id, []))
        vuln['cisa_kev'] = dict(
            self._kev[cve_id]
        ) if cve_id in self._kev else None
        vuln['sandbox_runs'] = list(self._sandbox.get(cve_id, []))
        return vuln

    def _require(self, cve_id: str) -> Dict[str, Any]:
        """get vuln or raise if not found"""
        vuln = self._vulns.get(cve_id)
        if vuln is None:
            raise ValueError(f"Vulnerability {cve_id} not found")
        return vuln

    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> None:
        vuln = self._require(cve_id)
        entry = dict(exploit_data)
        entry.setdefault('id', len(self._exploits.get(cve_id, [])) + 1)
        entry['vulnerability_id'] = vuln['id']
        self._exploits.setdefault(cve_id, []).append(entry)

        # keep summary flags in sync
        vuln['has_exploit'] = True
        vuln['exploit_count'] = len(self._exploits[cve_id])
        vuln['criticality_score'] = _calculate_criticality(vuln)

    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> None:
        vuln = self._require(cve_id)
        entry = dict(kev_data)
        entry['vulnerability_id'] = vuln['id']
        self._kev[cve_id] = entry

        vuln['in_cisa_kev'] = True
        if kev_data.get('known_ransomware'):
            vuln['known_ransomware'] = True
        vuln['criticality_score'] = _calculate_criticality(vuln)

    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> None:
        vuln = self._require(cve_id)
        entry = dict(sandbox_data)
        entry.setdefault('id', len(self._sandbox.get(cve_id, [])) + 1)
        entry['vulnerability_id'] = vuln['id']
        self._sandbox.setdefault(cve_id, []).append(entry)

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        return list(self._sandbox.get(cve_id, []))

    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str = None
    ) -> None:
        vuln = self._require(cve_id)
        entry = {
            'id': len(self._refs.get(cve_id, [])) + 1,
            'vulnerability_id': vuln['id'],
            'url': url, 'ref_type': ref_type, 'source': source,
        }
        self._refs.setdefault(cve_id, []).append(entry)

        if ref_type == "GITHUB" or source == "GitHub":
            vuln['github_refs'] = vuln.get('github_refs', 0) + 1
        elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
            vuln['exploitdb_refs'] = vuln.get('exploitdb_refs', 0) + 1
        vuln['criticality_score'] = _calculate_criticality(vuln)

    def search(
        self, min_cvss: float = None, severity: str = None,
        has_exploit: bool = None, in_cisa_kev: bool = None,
        min_criticality: int = None,
        limit: int = 100, offset: int = 0,
    ) -> List[Dict[str, Any]]:
        results = []
        for vuln in self._vulns.values():
            if min_cvss is not None:
                if (vuln.get('cvss_v3_score') or 0) < min_cvss:
                    continue
            if severity and vuln.get('severity') != severity:
                continue
            if has_exploit and not vuln.get('has_exploit'):
                continue
            if in_cisa_kev and not vuln.get('in_cisa_kev'):
                continue
            if min_criticality is not None:
                if (vuln.get('criticality_score') or 0) < min_criticality:
                    continue
            results.append(dict(vuln))

        results.sort(
            key=lambda v: (
                v.get('criticality_score') or 0,
                v.get('cvss_v3_score') or 0,
            ),
            reverse=True,
        )
        return results[offset: offset + limit]

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
            sev = v.get('severity')
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + 1
            score = v.get('cvss_v3_score')
            if score is not None:
                cvss_sum += score
                cvss_count += 1

        ransomware = sum(
            1 for k in self._kev.values() if k.get('known_ransomware'))

        return {
            'total': len(vulns),
            'by_severity': by_severity,
            'with_exploits': sum(1 for v in vulns if v.get('has_exploit')),
            'in_cisa_kev': sum(1 for v in vulns if v.get('in_cisa_kev')),
            'ransomware_related': ransomware,
            'critical_count': sum(
                1 for v in vulns if (v.get('criticality_score') or 0) >= 60),
            'avg_cvss': round(cvss_sum / cvss_count, 2) if cvss_count else 0,
        }

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


if __name__ == "__main__":
    passed = 0
    failed = 0

    def check(label, condition):
        global passed, failed
        if condition:
            print(f"  ok  {label}")
            passed += 1
        else:
            print(f"  FAIL {label}")
            failed += 1

    print("running InMemoryThreatDB tests...")

    db = InMemoryThreatDB()

    # basic upsert and fetch
    vid = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-1086',
        'description': 'Critical RCE vulnerability',
        'published_date': '2024-01-15',
        'cvss_v3_score': 9.8,
        'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'CRITICAL',
        'cwe_ids': ['CWE-89'],
        'sources': ['NIST_NVD'],
    })
    check("upsert returns int id", isinstance(vid, int) and vid >= 1)

    vuln = db.get_vulnerability('CVE-2024-1086')
    check("get_vulnerability not None", vuln is not None)
    check("severity stored correctly", vuln['severity'] == 'CRITICAL')
    check("cvss stored correctly", vuln['cvss_v3_score'] == 9.8)

    # update path keeps same id
    vid2 = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-1086',
        'description': 'Updated description',
        'cvss_v3_score': 9.8,
        'severity': 'CRITICAL',
    })
    check("upsert update keeps same id", vid == vid2)
    check("description updated", db.get_vulnerability(
        'CVE-2024-1086')['description'] == 'Updated description')

    # missing cve returns None
    check(
        "missing cve returns None",
        db.get_vulnerability('CVE-9999-9999') is None
    )

    # exploit tracking
    db.add_exploit('CVE-2024-1086', {
        'exploit_type': 'POC', 'source': 'GitHub',
        'url': 'https://github.com/user/exploit', 'verified': True,
    })
    vuln = db.get_vulnerability('CVE-2024-1086')
    check("add_exploit sets has_exploit flag", vuln['has_exploit'] is True)
    check("exploit_count incremented", vuln['exploit_count'] == 1)

    # second exploit bumps count
    db.add_exploit('CVE-2024-1086', {
        'exploit_type': 'POC', 'source': 'Exploit-DB', 'verified': False,
    })
    check("exploit_count after second add", db.get_vulnerability(
        'CVE-2024-1086')['exploit_count'] == 2)

    # cisa kev tracking
    db.add_cisa_kev('CVE-2024-1086', {
        'date_added': '2024-01-20',
        'required_action': 'Apply updates',
        'known_ransomware': True,
    })
    vuln = db.get_vulnerability('CVE-2024-1086')
    check("add_cisa_kev sets in_cisa_kev", vuln['in_cisa_kev'] is True)
    check("criticality maxes out at 100", vuln['criticality_score'] == 100)

    # reference tracking updates github_refs
    db.add_reference('CVE-2024-1086',
                     url='https://github.com/user/poc',
                     ref_type='GITHUB', source='GitHub')
    vuln = db.get_vulnerability('CVE-2024-1086')
    check("add_reference increments github_refs", vuln['github_refs'] == 1)

    # sandbox run round-trip
    db.add_sandbox_run('CVE-2024-1086', {
        'run_timestamp': '2024-01-21T10:30:00',
        'sandbox_platform': 'virtme-ng',
        'exploit_file_hash': 'a1b2c3d4e5f6',
        'execution_success': True, 'exit_code': 0,
        'stdout': 'Exploit executed\nRoot shell obtained\n',
        'stderr': 'Warning: deprecated syscall\n',
        'stdin': './xpl\n',
        'open_processes': ['/bin/sh', '/tmp/xpl'],
        'open_files': ['/etc/passwd', '/proc/self/maps'],
        'notes': 'Confirmed RCE, spawns reverse shell',
    })
    runs = db.get_sandbox_runs('CVE-2024-1086')
    check("get_sandbox_runs returns 1 run", len(runs) == 1)
    check(
        "sandbox platform stored",
        runs[0]['sandbox_platform'] == 'virtme-ng'
    )
    check(
        "sandbox hash stored",
        runs[0]['exploit_file_hash'] == 'a1b2c3d4e5f6'
    )
    check("execution_success stored", runs[0]['execution_success'] is True)

    # get_vulnerability_with_details includes all tables
    full = db.get_vulnerability_with_details('CVE-2024-1086')
    check("details has 2 exploits", len(full['exploits']) == 2)
    check("details has cisa_kev", full['cisa_kev'] is not None)
    check(
        "details cisa_kev known_ransomware",
        full['cisa_kev']['known_ransomware'] is True
    )
    check("details has 1 reference", len(full['references']) == 1)
    check("details has 1 sandbox_run", len(full['sandbox_runs']) == 1)

    # add second low-severity vuln for search tests
    db.upsert_vulnerability({
        'cve_id': 'CVE-2024-1086',
        'description': 'Low severity info disclosure',
        'cvss_v3_score': 3.1,
        'severity': 'LOW',
        'sources': ['OSV'],
    })

    check("search by severity CRITICAL returns 1",
          len(db.search(severity='CRITICAL')) == 1)
    check("search by severity LOW returns 1",
          len(db.search(severity='LOW')) == 1)
    check("search min_cvss=9.0 returns 1",
          len(db.search(min_cvss=9.0)) == 1)
    check("search min_cvss=3.0 returns 2",
          len(db.search(min_cvss=3.0)) == 2)
    check("search has_exploit returns 1",
          len(db.search(has_exploit=True)) == 1)
    check("search in_cisa_kev returns 1",
          len(db.search(in_cisa_kev=True)) == 1)
    check("search min_criticality=60 returns 1",
          len(db.search(min_criticality=60)) == 1)

    # pagination
    check("search offset=1 returns 1",
          len(db.search(min_cvss=3.0, limit=10, offset=1)) == 1)

    # convenience wrappers
    check("get_critical returns 1", len(db.get_critical()) == 1)
    check("get_with_exploits returns 1", len(db.get_with_exploits()) == 1)
    check("get_cisa_kev_list returns 1", len(db.get_cisa_kev_list()) == 1)

    # bulk_insert
    inserted = db.bulk_insert([
        {
            'cve_id': 'CVE-2024-0010',
            'cvss_v3_score': 7.5, 'severity': 'HIGH'},
        {
            'cve_id': 'CVE-2024-0011',
            'cvss_v3_score': 6.0, 'severity': 'MEDIUM'},
    ])
    check("bulk_insert returns count 2", inserted == 2)

    # stats
    stats = db.get_statistics()
    check("stats total == 4", stats['total'] == 4)
    check(
        "stats by_severity has CRITICAL",
        stats['by_severity'].get('CRITICAL') == 1
    )
    check("stats with_exploits == 1", stats['with_exploits'] == 1)
    check("stats in_cisa_kev == 1", stats['in_cisa_kev'] == 1)
    check("stats ransomware_related == 1", stats['ransomware_related'] == 1)
    check("stats critical_count == 1", stats['critical_count'] == 1)
    check("stats avg_cvss > 0", stats['avg_cvss'] > 0)

    # _require raises on unknown cve
    try:
        db._require('CVE-9999-9999')
        check("_require raises ValueError", False)
    except ValueError:
        check("_require raises ValueError", True)

    db.close()
    print(f"\n{passed} passed, {failed} failed")
