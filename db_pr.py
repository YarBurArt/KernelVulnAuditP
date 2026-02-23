import sqlite3
import json
from typing import List, Dict, Any, Optional
from contextlib import contextmanager


class SimpleThreatDB:
    def __init__(self, db_path: str = "threat_intel_simple.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _get_conn(self):
        if self.conn is None:
            self.conn = sqlite3.connect(
                self.db_path, check_same_thread=False
            )
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys = ON")
        return self.conn

    @contextmanager
    def transaction(self):
        """transaction context manager"""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def _init_db(self):
        """create base schema"""
        conn = self._get_conn()

        # base vuln table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                cvss_v3_vector TEXT,
                severity TEXT,
                cwe_ids TEXT,
                in_cisa_kev INTEGER DEFAULT 0,
                has_exploit INTEGER DEFAULT 0,
                exploit_count INTEGER DEFAULT 0,
                github_refs INTEGER DEFAULT 0,
                exploitdb_refs INTEGER DEFAULT 0,
                sources TEXT,
                raw_data TEXT,
                criticality_score INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve ON vulnerabilities(cve_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cvss3 ON vulnerabilities(cvss_v3_score)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_kev ON vulnerabilities(in_cisa_kev)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_exploit ON vulnerabilities(has_exploit)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_criticality ON vulnerabilities(criticality_score)")

        # Affected products/packages to further support vulns like in sudo, GNU utils
        conn.execute("""
            CREATE TABLE IF NOT EXISTS affected_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                vendor TEXT,
                product TEXT,
                version TEXT,
                cpe TEXT,
                package_ecosystem TEXT,
                package_name TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_id ON affected_products(vulnerability_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_product ON affected_products(vendor, product)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_package ON affected_products(package_ecosystem, package_name)")

        # References (all links in one table)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                ref_type TEXT,
                source TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_ref_vuln ON references(vulnerability_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ref_type ON references(ref_type)")

        # CISA KEV data
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cisa_kev (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER UNIQUE NOT NULL,
                date_added TEXT,
                due_date TEXT,
                required_action TEXT,
                known_ransomware INTEGER DEFAULT 0,
                vendor_project TEXT,
                product TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_kev_vuln ON cisa_kev(vulnerability_id)")

        # known xpl table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                exploit_type TEXT,
                source TEXT,
                url TEXT,
                verified INTEGER DEFAULT 0,
                date_published TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_exploit_vuln ON exploits(vulnerability_id)")

        # sandbox virt like runs table (minimal for isolate)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                run_timestamp TEXT,
                sandbox_platform TEXT,
                exploit_file_hash TEXT,
                execution_success INTEGER DEFAULT 0,
                exit_code INTEGER,
                stdout TEXT,
                stderr TEXT,
                stdin TEXT,
                open_processes TEXT,
                open_files TEXT,
                notes TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_vuln ON sandbox_runs(vulnerability_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sandbox_hash ON sandbox_runs(exploit_file_hash)")

        conn.commit()

    def upsert_vulnerability(self, data: Dict[str, Any]) -> int:
        """
        update vuln by data: Dict with keys like cve_id,
        description, cvss_v3_score, severity, etc.
        """
        conn = self._get_conn()
        cursor = conn.execute("SELECT id FROM vulnerabilities WHERE cve_id = ?", (data['cve_id'],))
        existing = cursor.fetchone()
        criticality = self._calculate_criticality(data)
        sources = data.get('sources', [])
        if isinstance(sources, list):
            sources = json.dumps(sources)
        cwe_ids = data.get('cwe_ids', [])
        if isinstance(cwe_ids, list):
            cwe_ids = json.dumps(cwe_ids)

        raw_data = json.dumps(data.get('raw_data', {}))

        if existing:
            # Update
            conn.execute("""
                UPDATE vulnerabilities
                SET description = ?, published_date = ?, last_modified_date = ?,
                    cvss_v2_score = ?, cvss_v3_score = ?, cvss_v3_vector = ?,
                    severity = ?, cwe_ids = ?, in_cisa_kev = ?, has_exploit = ?,
                    exploit_count = ?, github_refs = ?, exploitdb_refs = ?,
                    sources = ?, raw_data = ?, criticality_score = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE cve_id = ?
            """, (
                data.get('description'),
                data.get('published_date'),
                data.get('last_modified_date'),
                data.get('cvss_v2_score'),
                data.get('cvss_v3_score'),
                data.get('cvss_v3_vector'),
                data.get('severity'),
                cwe_ids,
                1 if data.get('in_cisa_kev') else 0,
                1 if data.get('has_exploit') else 0,
                data.get('exploit_count', 0),
                data.get('github_refs', 0),
                data.get('exploitdb_refs', 0),
                sources,
                raw_data,
                criticality,
                data['cve_id']
            ))
            conn.commit()
            return existing[0]
        else:
            # Insert
            cursor = conn.execute("""
                INSERT INTO vulnerabilities
                (cve_id, description, published_date, last_modified_date,
                 cvss_v2_score, cvss_v3_score, cvss_v3_vector, severity, cwe_ids,
                 in_cisa_kev, has_exploit, exploit_count, github_refs, exploitdb_refs,
                 sources, raw_data, criticality_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['cve_id'],
                data.get('description'),
                data.get('published_date'),
                data.get('last_modified_date'),
                data.get('cvss_v2_score'),
                data.get('cvss_v3_score'),
                data.get('cvss_v3_vector'),
                data.get('severity'),
                cwe_ids,
                1 if data.get('in_cisa_kev') else 0,
                1 if data.get('has_exploit') else 0,
                data.get('exploit_count', 0),
                data.get('github_refs', 0),
                data.get('exploitdb_refs', 0),
                sources,
                raw_data,
                criticality
            ))
            conn.commit()
            return cursor.lastrowid

    def get_vulnerability(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        cursor = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()

        if row:
            return self._row_to_dict(row)
        return None

    def add_affected_product(
        self, vuln_id: int, product_data: Dict[str, Any]
    ):
        """affected product/package to further support vulns like in sudo, GNU utils"""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO affected_products
            (vulnerability_id, vendor, product, version, cpe, package_ecosystem, package_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            product_data.get('vendor'),
            product_data.get('product'),
            product_data.get('version'),
            product_data.get('cpe'),
            product_data.get('package_ecosystem'),
            product_data.get('package_name')
        ))
        conn.commit()

    def get_affected_products(
        self, vuln_id: int
    ) -> List[Dict[str, Any]]:
        """all affected products for vuln"""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM affected_products WHERE vulnerability_id = ?",
            (vuln_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def add_reference(
        self, vuln_id: int, url: str,
        ref_type: str = "OTHER", source: str = None
    ):
        """Add reference/link"""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO references (vulnerability_id, url, ref_type, source)
            VALUES (?, ?, ?, ?)
        """, (vuln_id, url, ref_type, source))
        conn.commit()

    def get_references(self, vuln_id: int) -> List[Dict[str, Any]]:
        """all refs for vuln"""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM references WHERE vulnerability_id = ?",
            (vuln_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def add_exploit(self, vuln_id: int, exploit_data: Dict[str, Any]):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO exploits
            (vulnerability_id, exploit_type, source, url, verified, date_published)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            exploit_data.get('exploit_type'),
            exploit_data.get('source'),
            exploit_data.get('url'),
            1 if exploit_data.get('verified') else 0,
            exploit_data.get('date_published')
        ))
        conn.commit()

        # update exploit flags on main table
        conn.execute("""
            UPDATE vulnerabilities
            SET has_exploit = 1,
                exploit_count = (SELECT COUNT(*) FROM exploits WHERE vulnerability_id = ?)
            WHERE id = ?
        """, (vuln_id, vuln_id))
        conn.commit()

    def get_exploits(self, vuln_id: int) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM exploits WHERE vulnerability_id = ?",
            (vuln_id,)
        )
        return [dict(row) for row in cursor.fetchall()]

    def add_cisa_kev(self, vuln_id: int, kev_data: Dict[str, Any]):
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO cisa_kev
            (vulnerability_id, date_added, due_date, required_action,
             known_ransomware, vendor_project, product)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            kev_data.get('date_added'),
            kev_data.get('due_date'),
            kev_data.get('required_action'),
            1 if kev_data.get('known_ransomware') else 0,
            kev_data.get('vendor_project'),
            kev_data.get('product')
        ))
        conn.commit()
        # add KEV flag
        conn.execute("UPDATE vulnerabilities SET in_cisa_kev = 1 WHERE id = ?", (vuln_id,))
        conn.commit()

    def get_cisa_kev(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        """Get CISA KEV entry"""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM cisa_kev WHERE vulnerability_id = ?",
            (vuln_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def add_sandbox_run(
        self, vuln_id: int, sandbox_data: Dict[str, Any]
    ):
        """Add isolated execution data"""
        conn = self._get_conn()

        # convert list fields to JSON
        open_processes = sandbox_data.get('open_processes')
        if isinstance(open_processes, list):
            open_processes = json.dumps(open_processes)

        open_files = sandbox_data.get('open_files')
        if isinstance(open_files, list):
            open_files = json.dumps(open_files)

        conn.execute("""
            INSERT INTO sandbox_runs
            (vulnerability_id, run_timestamp, sandbox_platform, exploit_file_hash,
             execution_success, exit_code, stdout, stderr, stdin,
             open_processes, open_files, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id,
            sandbox_data.get('run_timestamp'),
            sandbox_data.get('sandbox_platform'),
            sandbox_data.get('exploit_file_hash'),
            1 if sandbox_data.get('execution_success') else 0,
            sandbox_data.get('exit_code'),
            sandbox_data.get('stdout'),
            sandbox_data.get('stderr'),
            sandbox_data.get('stdin'),
            open_processes,
            open_files,
            sandbox_data.get('notes')
        ))
        conn.commit()

    def get_sandbox_runs(self, vuln_id: int) -> List[Dict[str, Any]]:
        """get all xpl runs for vuln"""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM sandbox_runs WHERE vulnerability_id = ? ORDER BY run_timestamp DESC",
            (vuln_id,)
        )
        runs = []
        for row in cursor.fetchall():
            run_dict = dict(row)
            for field in ['open_processes', 'open_files']:
                if run_dict.get(field):
                    try:
                        run_dict[field] = json.loads(run_dict[field])
                    except:
                        pass

            # convert boolean flags
            run_dict['execution_success'] = bool(
                run_dict.get('execution_success'))

            runs.append(run_dict)

        return runs

    def get_cisa_kev_n(self, vuln_id: int) -> Optional[Dict[str, Any]]:
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM cisa_kev WHERE vulnerability_id = ?",
            (vuln_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def get_full_vulnerability(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        vuln = self.get_vulnerability(cve_id)
        if not vuln:
            return None

        vuln_id = vuln['id']
        vuln['affected_products'] = self.get_affected_products(vuln_id)
        vuln['references'] = self.get_references(vuln_id)
        vuln['exploits'] = self.get_exploits(vuln_id)
        vuln['cisa_kev'] = self.get_cisa_kev(vuln_id)
        vuln['sandbox_runs'] = self.get_sandbox_runs(vuln_id)

        return vuln

    def search(
        self,
        min_cvss: float = None,
        severity: str = None,
        has_exploit: bool = None,
        in_cisa_kev: bool = None,
        min_criticality: int = None,
        vendor: str = None,
        product: str = None,
        package_ecosystem: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Search vulnerabilities with filters"""
        conn = self._get_conn()

        query = "SELECT DISTINCT v.* FROM vulnerabilities v"
        joins = []
        conditions = []
        params = []

        if min_cvss is not None:
            conditions.append("v.cvss_v3_score >= ?")
            params.append(min_cvss)

        if severity:
            conditions.append("v.severity = ?")
            params.append(severity)

        if has_exploit: conditions.append("v.has_exploit = 1")

        if in_cisa_kev: conditions.append("v.in_cisa_kev = 1")

        if min_criticality is not None:
            conditions.append("v.criticality_score >= ?")
            params.append(min_criticality)

        if vendor or product or package_ecosystem:
            joins.append("LEFT JOIN affected_products ap ON v.id = ap.vulnerability_id")
            if vendor:
                conditions.append("ap.vendor LIKE ?")
                params.append(f"%{vendor}%")
            if product:
                conditions.append("ap.product LIKE ?")
                params.append(f"%{product}%")
            if package_ecosystem:
                conditions.append("ap.package_ecosystem = ?")
                params.append(package_ecosystem)

        if joins: query += " " + " ".join(joins)

        if conditions: query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY v.criticality_score DESC, v.cvss_v3_score DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = conn.execute(query, params)
        return [self._row_to_dict(row) for row in cursor.fetchall()]

    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.search(min_criticality=60, limit=limit)

    def get_by_severity(
        self, severity: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.search(severity=severity, limit=limit)

    def get_with_exploits(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.search(has_exploit=True, limit=limit)

    def get_cisa_kev_list(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.search(in_cisa_kev=True, limit=limit)

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = self._get_conn()
        stats = {}

        cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total'] = cursor.fetchone()[0]

        cursor = conn.execute("SELECT severity, COUNT(*) FROM vulnerabilities WHERE severity IS NOT NULL GROUP BY severity")
        stats['by_severity'] = dict(cursor.fetchall())
        cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE has_exploit = 1")
        stats['with_exploits'] = cursor.fetchone()[0]
        cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE in_cisa_kev = 1")
        stats['in_cisa_kev'] = cursor.fetchone()[0]
        cursor = conn.execute("SELECT COUNT(*) FROM cisa_kev WHERE known_ransomware = 1")
        stats['ransomware_related'] = cursor.fetchone()[0]
        cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE criticality_score >= 60")
        stats['critical_count'] = cursor.fetchone()[0]
        cursor = conn.execute("SELECT AVG(cvss_v3_score) FROM vulnerabilities WHERE cvss_v3_score IS NOT NULL")
        result = cursor.fetchone()[0]

        stats['avg_cvss'] = round(result, 2) if result else 0

        return stats

    def _calculate_criticality(self, data: Dict[str, Any]) -> int:
        """criticality score (0-100)"""
        score = 0
        # CISA KEV
        if data.get('in_cisa_kev'):
            score += 40
            if data.get('known_ransomware'):
                score += 20
        # loaded xpl
        if data.get('has_exploit'):
            score += 25
            score += min(data.get('exploit_count', 0) * 2, 10)

        cvss = data.get('cvss_v3_score') or data.get('cvss_v2_score') or 0
        score += int(cvss * 2) 
        score += min(data.get('github_refs', 0) * 3, 15)
        score += min(data.get('exploitdb_refs', 0) * 3, 15)

        return min(score, 100)

    def _row_to_dict(self, row) -> Dict[str, Any]:
        d = dict(row)
        if d.get('sources'):
            try:
                d['sources'] = json.loads(d['sources'])
            except Exception:
                d['sources'] = []

        if d.get('cwe_ids'):
            try:
                d['cwe_ids'] = json.loads(d['cwe_ids'])
            except Exception:
                d['cwe_ids'] = []

        if d.get('raw_data'):
            try:
                d['raw_data'] = json.loads(d['raw_data'])
            except Exception:
                d['raw_data'] = {}

        # Convert boolean flags
        d['in_cisa_kev'] = bool(d.get('in_cisa_kev'))
        d['has_exploit'] = bool(d.get('has_exploit'))

        return d

    def bulk_insert(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> int:
        """Bulk insert vulnerabilities (faster for large datasets)"""
        count = 0
        with self.transaction():
            for vuln_data in vulnerabilities:
                try:
                    self.upsert_vulnerability(vuln_data)
                    count += 1
                except Exception as e:
                    print(f"Error inserting {vuln_data.get('cve_id')}: {e}")
        return count

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


if __name__ == "__main__":
    db = SimpleThreatDB()

    # sample vulnerability
    vuln_id = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-1234',
        'description': 'Critical RCE vulnerability',
        'published_date': '2024-01-15',
        'cvss_v3_score': 9.8,
        'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'CRITICAL',
        'cwe_ids': ['CWE-89', 'CWE-79'],
        'in_cisa_kev': True,
        'has_exploit': True,
        'exploit_count': 2,
        'github_refs': 3,
        'sources': ['NIST_NVD', 'CISA_KEV', 'OSV']
    })

    # add related data
    db.add_affected_product(vuln_id, {
        'vendor': 'Apache',
        'product': 'Struts',
        'version': '2.5.x'
    })

    db.add_exploit(vuln_id, {
        'exploit_type': 'POC',
        'source': 'GitHub',
        'url': 'https://github.com/user/exploit',
        'verified': True
    })

    db.add_cisa_kev(vuln_id, {
        'date_added': '2024-01-20',
        'required_action': 'Apply updates',
        'known_ransomware': True
    })

    # sample isolate data
    db.add_sandbox_run(vuln_id, {
        'run_timestamp': '2024-01-21T10:30:00', 'sandbox_platform': 'virtme-ng',
        'exploit_file_hash': 'a1b2c3d4e5f6...', 'execution_success': True,
        'exit_code': 0,
        'stdout': 'Exploit executed successfully\nRoot shell obtained\n',
        'stderr': 'Warning: deprecated syscall\n',
        'stdin': './xpl\n',
        'open_processes': ['/bin/sh', '/tmp/xpl', '/bin/nc', 'python3'],
        'open_files': [
            '/tmp/exploit',
            '/tmp/.hidden',
            '/proc/self/maps',
            '/etc/passwd'
        ],
        'notes': 'Confirmed RCE, spawns reverse shell'
    })

    critical = db.get_critical(limit=10)
    print(f"Found {len(critical)} critical vulnerabilities")

    stats = db.get_statistics()
    print(f"Stats: {stats}")

    db.close()
