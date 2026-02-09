from sqlalchemy import (
    create_engine, Column, Integer, String, 
    Float, Boolean, Text, DateTime,
    ForeignKey, Index, JSON, Table, func
)
from sqlalchemy.orm import (
    declarative_base, relationship, Session,
    sessionmaker, scoped_session
)
from sqlalchemy.pool import StaticPool
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

Base = declarative_base()


class Vulnerability(Base):
    """Main vulnerability table"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    
    # CVSS scores
    cvss_v2_score = Column(Float)
    cvss_v3_score = Column(Float, index=True)
    cvss_v3_vector = Column(String(200))
    
    # Metadata
    severity = Column(String(20), index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_ids = Column(JSON)  # List of CWE IDs
    
    # flags for quick filtering
    in_cisa_kev = Column(Boolean, default=False, index=True)
    has_exploit = Column(Boolean, default=False, index=True)
    exploit_count = Column(Integer, default=0)
    github_refs = Column(Integer, default=0)
    exploitdb_refs = Column(Integer, default=0)
    
    sources = Column(JSON)  # List of sources: NIST, CISA, OSV, etc.
    raw_data = Column(JSON)  # Store complete raw API responses
    criticality_score = Column(Integer, default=0, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    affected_products = relationship("AffectedProduct", back_populates="vulnerability", cascade="all, delete-orphan")
    references = relationship("Reference", back_populates="vulnerability", cascade="all, delete-orphan")
    exploits = relationship("Exploit", back_populates="vulnerability", cascade="all, delete-orphan")
    cisa_kev = relationship("CISAKEVEntry", back_populates="vulnerability", uselist=False, cascade="all, delete-orphan")
    sandbox_runs = relationship("SandboxRun", back_populates="vulnerability", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict[str, Any]:
        """convert to dictionary for json and report"""
        return {
            'id': self.id, 'cve_id': self.cve_id, 'description': self.description,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'cvss_v2_score': self.cvss_v2_score, 'cvss_v3_score': self.cvss_v3_score,
            'cvss_v3_vector': self.cvss_v3_vector, 'severity': self.severity,
            'cwe_ids': self.cwe_ids or [], 'in_cisa_kev': self.in_cisa_kev,
            'has_exploit': self.has_exploit, 'exploit_count': self.exploit_count,
            'github_refs': self.github_refs, 'exploitdb_refs': self.exploitdb_refs,
            'sources': self.sources or [], 'criticality_score': self.criticality_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def calculate_criticality(self):
        """ internal calc crit """
        score = 0
        if self.in_cisa_kev:
            score += 40
            if self.cisa_kev and self.cisa_kev.known_ransomware:
                score += 20
        if self.has_exploit:
            score += 25
            score += min(self.exploit_count * 2, 10)
        
        cvss = self.cvss_v3_score or self.cvss_v2_score or 0
        score += int(cvss * 2)
        score += min(self.github_refs * 3, 15)
        score += min(self.exploitdb_refs * 3, 15)
        
        self.criticality_score = min(score, 100)
        return self.criticality_score


class AffectedProduct(Base):
    """Products/packages affected by vulnerabilities
    for track also like GNU utils vulns"""
    __tablename__ = 'affected_products'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # CPE-style identification
    vendor = Column(String(200), index=True)
    product = Column(String(200), index=True)
    version = Column(String(100))
    cpe = Column(String(500))
    
    # OSV-style identification
    package_ecosystem = Column(String(50), index=True)
    package_name = Column(String(200), index=True)
    
    # Relationship to vulns
    vulnerability = relationship("Vulnerability", back_populates="affected_products")
    
    __table_args__ = (
        Index('idx_vendor_product', 'vendor', 'product'),
        Index('idx_package', 'package_ecosystem', 'package_name'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'vendor': self.vendor, 'product': self.product,
            'version': self.version, 'cpe': self.cpe,
            'package_ecosystem': self.package_ecosystem,
            'package_name': self.package_name
        }


class Reference(Base):
    """any external references and links"""
    __tablename__ = 'references'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False, index=True)
    
    url = Column(String(1000), nullable=False)
    ref_type = Column(String(50), index=True)  # ADVISORY, EXPLOIT, PATCH, GITHUB, EXPLOIT_DB, etc.
    source = Column(String(100))  # like "GitHub", "Exploit-DB", "NVD"
    
    # Relationship to vulns
    vulnerability = relationship("Vulnerability", back_populates="references")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'url': self.url,
            'ref_type': self.ref_type,
            'source': self.source
        }


class Exploit(Base):
    """known loaded exploits"""
    __tablename__ = 'exploits'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False, index=True)
    
    exploit_type = Column(String(50))  # POC, DoS, etc.
    source = Column(String(100))  # GitHub, Exploit-DB, searchsploit, etc.
    url = Column(String(1000))
    verified = Column(Boolean, default=False, index=True)
    date_published = Column(DateTime)
    
    # Relationship to vulns
    vulnerability = relationship("Vulnerability", back_populates="exploits")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'exploit_type': self.exploit_type, 'source': self.source,
            'url': self.url, 'verified': self.verified,
            'date_published': self.date_published.isoformat() if self.date_published else None
        }


class CISAKEVEntry(Base):
    """CISA Known Exploited Vulnerabilities catalog, filtered feed"""
    __tablename__ = 'cisa_kev'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'),
        unique=True, nullable=False, index=True
    )
    date_added = Column(DateTime)
    due_date = Column(DateTime)
    required_action = Column(Text)
    known_ransomware = Column(Boolean, default=False, index=True)
    notes = Column(Text)
    vendor_project = Column(String(200))
    product = Column(String(200))
    
    # Relationship to vulns
    vulnerability = relationship("Vulnerability", back_populates="cisa_kev")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'date_added': self.date_added.isoformat() if self.date_added else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'required_action': self.required_action,
            'known_ransomware': self.known_ransomware,
            'notes': self.notes, 'vendor_project': self.vendor_project,
            'product': self.product
        }


class SandboxRun(Base):
    """execution data for exploits (minimal virtme-ng)"""
    __tablename__ = 'sandbox_runs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id', ondelete='CASCADE'), nullable=False, index=True)
    
    run_timestamp = Column(DateTime)
    sandbox_platform = Column(String(100))  # virtme-ng, qemu, host
    exploit_file_hash = Column(String(128), index=True)  # SHA256 of analyzed file
    execution_success = Column(Boolean, default=False)
    exit_code = Column(Integer)
    stdout = Column(Text)
    stderr = Column(Text)
    stdin = Column(Text)
    open_processes = Column(JSON)  # List of processes running during execution
    open_files = Column(JSON)  # List of files opened during execution
    notes = Column(Text)

    # Relationship to vulns
    vulnerability = relationship("Vulnerability", back_populates="sandbox_runs")
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'run_timestamp': self.run_timestamp.isoformat() if self.run_timestamp else None,
            'sandbox_platform': self.sandbox_platform, 'exploit_file_hash': self.exploit_file_hash,
            'execution_success': self.execution_success, 'exit_code': self.exit_code,
            'stdout': self.stdout, 'stderr': self.stderr,
            'stdin': self.stdin, 'open_processes': self.open_processes,
            'open_files': self.open_files, 'notes': self.notes
        }


class ThreatIntelligenceORM:
    """db manager"""
    
    def __init__(self, db_url: str = "sqlite:///ti.db"):
        self.engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {},
            poolclass=StaticPool if db_url == "sqlite:///:memory:" else None
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.ScopedSession = scoped_session(self.SessionLocal)
    
    def get_session(self) -> Session:
        return self.SessionLocal()
    
    def upsert_vulnerability(self, data: Dict[str, Any]) -> Vulnerability:
        """add or update vulnerability"""
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=data['cve_id']).first()
            if vuln:
                for key, value in data.items():
                    if hasattr(vuln, key) and key != 'id':
                        setattr(vuln, key, value)
            else:
                vuln = Vulnerability(**data)
                session.add(vuln)
            vuln.calculate_criticality()
            
            session.commit()
            session.refresh(vuln)
            return vuln
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        session = self.get_session()
        try:
            return session.query(Vulnerability).filter_by(cve_id=cve_id).first()
        finally:
            session.close()
    
    def get_vulnerability_with_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln: return None
            
            result = vuln.to_dict()
            result['affected_products'] = [p.to_dict() for p in vuln.affected_products]
            result['references'] = [r.to_dict() for r in vuln.references]
            result['exploits'] = [e.to_dict() for e in vuln.exploits]
            result['cisa_kev'] = vuln.cisa_kev.to_dict() if vuln.cisa_kev else None
            result['sandbox_runs'] = [s.to_dict() for s in vuln.sandbox_runs]
            
            return result
        finally:
            session.close()
    
    def add_affected_product(self, cve_id: str, product_data: Dict[str, Any]) -> AffectedProduct:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                raise ValueError(f"Vulnerability {cve_id} not found")
            
            product = AffectedProduct(vulnerability_id=vuln.id, **product_data)
            session.add(product)
            session.commit()
            session.refresh(product)
            return product
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def add_reference(self, cve_id: str, url: str, ref_type: str = "OTHER", source: str = None) -> Reference:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                raise ValueError(f"Vulnerability {cve_id} not found")
            
            # Update counts
            if ref_type == "GITHUB" or source == "GitHub":
                vuln.github_refs += 1
            elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
                vuln.exploitdb_refs += 1
            
            ref = Reference(
                vulnerability_id=vuln.id,url=url,
                ref_type=ref_type, source=source)
            session.add(ref)
            
            vuln.calculate_criticality()
            session.commit()
            session.refresh(ref)
            return ref
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def add_exploit(self, cve_id: str, exploit_data: Dict[str, Any]) -> Exploit:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln: return  # FIXME 
            exploit = Exploit(vulnerability_id=vuln.id, **exploit_data)
            session.add(exploit)
        
            # update flags
            vuln.has_exploit = True
            vuln.exploit_count = session.query(Exploit).filter_by(vulnerability_id=vuln.id).count() + 1
            vuln.calculate_criticality()
            
            session.commit()
            session.refresh(exploit)
            return exploit
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def add_cisa_kev(self, cve_id: str, kev_data: Dict[str, Any]) -> CISAKEVEntry:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln: return
            # Remove existing KEV entry if any
            existing = session.query(CISAKEVEntry).filter_by(vulnerability_id=vuln.id).first()
            if existing:
                session.delete(existing)
            
            kev = CISAKEVEntry(vulnerability_id=vuln.id, **kev_data)
            session.add(kev)
            
            # Update flags
            vuln.in_cisa_kev = True
            vuln.calculate_criticality()
            
            session.commit()
            session.refresh(kev)
            return kev
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def add_sandbox_run(self, cve_id: str, sandbox_data: Dict[str, Any]) -> SandboxRun:
        """Add sandbox execution data"""
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                raise ValueError(f"Vulnerability {cve_id} not found")
            
            sandbox_run = SandboxRun(vulnerability_id=vuln.id, **sandbox_data)
            session.add(sandbox_run)
            session.commit()
            session.refresh(sandbox_run)
            return sandbox_run
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                return []
            
            runs = session.query(SandboxRun).filter_by(
                vulnerability_id=vuln.id
            ).order_by(SandboxRun.run_timestamp.desc()).all()
            
            return [run.to_dict() for run in runs]
        finally:
            session.close()
    
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
        """search vulns with filters"""
        session = self.get_session()
        try:
            query = session.query(Vulnerability)
            
            if min_cvss is not None:
                query = query.filter(Vulnerability.cvss_v3_score >= min_cvss)   
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            if has_exploit:
                query = query.filter(Vulnerability.has_exploit == True)
            if in_cisa_kev:
                query = query.filter(Vulnerability.in_cisa_kev == True)
            if min_criticality is not None:
                query = query.filter(Vulnerability.criticality_score >= min_criticality)
            if vendor or product or package_ecosystem:
                query = query.join(AffectedProduct)
                if vendor:
                    query = query.filter(AffectedProduct.vendor.like(f"%{vendor}%"))
                if product:
                    query = query.filter(AffectedProduct.product.like(f"%{product}%"))
                if package_ecosystem:
                    query = query.filter(AffectedProduct.package_ecosystem == package_ecosystem)
            
            # order by criticality and CVSS
            query = query.order_by(
                Vulnerability.criticality_score.desc(),
                Vulnerability.cvss_v3_score.desc()
            )
            
            results = query.limit(limit).offset(offset).all()
            return [v.to_dict() for v in results]
        finally:
            session.close()
    
    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.search(min_criticality=60, limit=limit)
    
    def get_with_exploits(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.search(has_exploit=True, limit=limit)
    
    def get_cisa_kev_list(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.search(in_cisa_kev=True, limit=limit)
    
    def get_statistics(self) -> Dict[str, Any]:
        session = self.get_session()
        try:
            stats = {}
            
            stats['total'] = session.query(Vulnerability).count()
            severity_counts = session.query(
                Vulnerability.severity,
                func.count(Vulnerability.id)
            ).filter(
                Vulnerability.severity.isnot(None)
            ).group_by(Vulnerability.severity).all()
            stats['by_severity'] = dict(severity_counts)
            
            stats['with_exploits'] = session.query(Vulnerability).filter_by(has_exploit=True).count()
            stats['in_cisa_kev'] = session.query(Vulnerability).filter_by(in_cisa_kev=True).count()
            stats['ransomware_related'] = session.query(CISAKEVEntry).filter_by(known_ransomware=True).count()
            stats['critical_count'] = session.query(Vulnerability).filter(Vulnerability.criticality_score >= 60).count()
            
            avg_cvss = session.query(func.avg(Vulnerability.cvss_v3_score)).scalar()
            stats['avg_cvss'] = round(avg_cvss, 2) if avg_cvss else 0
            
            return stats
        finally:
            session.close()
    
    def bulk_insert(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """bulk insert vulnerabilities"""
        session = self.get_session()
        count = 0
        try:
            for vuln_data in vulnerabilities:
                try:
                    self.upsert_vulnerability(vuln_data)
                    count += 1
                except Exception as e:
                    print(f"Error inserting {vuln_data.get('cve_id')}: {e}")
            session.commit()
            return count
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
    
    def close(self):
        self.ScopedSession.remove()
        self.engine.dispose()


if __name__ == "__main__":
    # only for testing
    db = ThreatIntelligenceORM("sqlite:///ti_test.db")
    
    # Add a sample vulnerability
    vuln = db.upsert_vulnerability({
        'cve_id': 'CVE-2024-5678',
        'description': 'Critical SQL injection vulnerability',
        'published_date': datetime(2024, 1, 15),
        'cvss_v3_score': 9.8,
        'cvss_v3_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'CRITICAL',
        'cwe_ids': ['CWE-89'],
        'sources': ['NIST_NVD', 'OSV']
    })
    
    print(f"Created vulnerability: {vuln.cve_id} with ID {vuln.id}")
    
    # Add a sample related data
    db.add_affected_product('CVE-2024-5678', {
        'vendor': 'Example Corp',
        'product': 'Framework',
        'version': '1.2.3',
        'package_ecosystem': 'rpm',
        'package_name': 'example-framework'
    })
    
    db.add_exploit('CVE-2024-5678', {
        'exploit_type': 'POC',
        'source': 'GitHub',
        'url': 'https://github.com/user/cve-2024-5678-poc',
        'verified': True
    })
    
    db.add_reference('CVE-2024-5678', 
        url='https://nvd.nist.gov/vuln/detail/CVE-2024-5678',
        ref_type='ADVISORY',
        source='NVD'
    )
    
    db.add_cisa_kev('CVE-2024-5678', {
        'date_added': datetime(2024, 1, 20),
        'required_action': 'Apply updates immediately',
        'known_ransomware': True,
        'vendor_project': 'Example Corp',
        'product': 'Web Framework'
    })
    
    # sample isolate runs
    db.add_sandbox_run('CVE-2024-5678', {
        'run_timestamp': datetime(2024, 1, 21, 10, 30),
        'sandbox_platform': 'virtme-ng',
        'exploit_file_hash': 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
        'execution_success': True,
        'exit_code': 0,
        'stdout': '''
            Exploit started...
            Got shell!
            # id
            uid=0(root) gid=0(root) groups=0(root)
            # whoami
            root
        ''',
        'stderr': 'Warning: deprecated syscall used\n',
        'stdin': './xpl\n',
        'open_processes': ['/bin/bash', '/tmp/xpl', '/bin/nc', 'python3' ],
        'open_files': ['/tmp/xpl', '/tmp/.shell_history', '/proc/self/maps',
            '/etc/passwd', '/dev/tcp/127.0.0.1/4'],
        'notes': 'Confirmed LPE'
    })

    full_data = db.get_vulnerability_with_details('CVE-2024-5678')
    print(f"""\nFull vulnerability data:
          Criticality: {full_data['criticality_score']}/100
          Exploits: {len(full_data['exploits'])}
          Sandbox Runs: {len(full_data['sandbox_runs'])}
          In CISA KEV: {full_data['in_cisa_kev']}""")
    
    stats = db.get_statistics()
    print(f"\nDatabase statistics: {stats}")
    critical = db.get_critical(limit=10)
    print(f"\nFound {len(critical)} critical vulnerabilities")
    
    db.close()
