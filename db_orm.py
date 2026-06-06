from __future__ import annotations
import logging
from sqlalchemy import (
    create_engine, Integer, String,
    Float, Boolean, Text, DateTime,
    ForeignKey, Index, JSON, func,
)
from sqlalchemy.orm import (
    DeclarativeBase, relationship, Session,
    sessionmaker, scoped_session,
    Mapped, mapped_column
)
from sqlalchemy.pool import StaticPool
from datetime import datetime
from typing import List, Dict, Any, Optional

from core import calculate_criticality_score


class Base(DeclarativeBase):
    pass

logger = logging.getLogger(f"kernel_audit.{__name__}")


class Vulnerability(Base):
    """Main vulnerability table"""
    __tablename__ = 'vulnerabilities'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    published_date: Mapped[datetime | None] = mapped_column(DateTime)
    last_modified_date: Mapped[datetime | None] = mapped_column(DateTime)

    # CVSS scores
    cvss_v2_score: Mapped[float | None] = mapped_column(Float)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(200))

    # Metadata
    severity: Mapped[str | None] = mapped_column(String(20), index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_ids: Mapped[list[str] | None] = mapped_column(JSON)  # List of CWE IDs

    # flags for quick filtering
    in_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_exploit: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploit_count: Mapped[int] = mapped_column(Integer, default=0)
    github_refs: Mapped[int] = mapped_column(Integer, default=0)
    exploitdb_refs: Mapped[int] = mapped_column(Integer, default=0)

    sources: Mapped[list[str] | None] = mapped_column(JSON)  # List of sources: NIST, CISA, OSV, etc.
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)  # Store complete raw API responses
    criticality_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    affected_products: Mapped[list[AffectedProduct]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    references: Mapped[list[Reference]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    exploits: Mapped[list[Exploit]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    cisa_kev: Mapped[CISAKEVEntry | None] = relationship(
        back_populates="vulnerability",
        uselist=False,
        cascade="all, delete-orphan",
    )
    sandbox_runs: Mapped[list[SandboxRun]] = relationship(
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )


    def to_dict(self) -> Dict[str, Any]:
        """convert to dictionary for json and report"""
        pd = self.published_date.isoformat() if self.published_date else None
        pmd = self.last_modified_date.isoformat() \
            if self.last_modified_date else None
        crt_at = self.created_at.isoformat() if self.created_at else None
        upd_at = self.updated_at.isoformat() if self.updated_at else None
        return {
            'id': self.id, 'cve_id': self.cve_id,
            'description': self.description,
            'published_date': pd,
            'last_modified_date': pmd,
            'cvss_v2_score': self.cvss_v2_score,
            'cvss_v3_score': self.cvss_v3_score,
            'cvss_v3_vector': self.cvss_v3_vector,
            'severity': self.severity,
            'cwe_ids': self.cwe_ids or [],
            'in_cisa_kev': self.in_cisa_kev,
            'has_exploit': self.has_exploit,
            'exploit_count': self.exploit_count,
            'github_refs': self.github_refs,
            'exploitdb_refs': self.exploitdb_refs,
            'sources': self.sources or [],
            'criticality_score': self.criticality_score,
            'created_at': crt_at,
            'updated_at': upd_at
        }

    def calculate_criticality(self):
        data = self.to_dict()
        if self.cisa_kev:
            data['known_ransomware'] = self.cisa_kev.known_ransomware
        self.criticality_score = calculate_criticality_score(data)
        return self.criticality_score


class AffectedProduct(Base):
    """Products/packages affected by vulnerabilities
    for track also like GNU utils vulns"""
    __tablename__ = 'affected_products'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # CPE-style identification
    vendor: Mapped[str | None] = mapped_column(String(200), index=True)
    product: Mapped[str | None] = mapped_column(String(200), index=True)
    version: Mapped[str | None] = mapped_column(String(100))
    cpe: Mapped[str | None] = mapped_column(String(500))

    # OSV-style identification
    package_ecosystem: Mapped[str | None] = mapped_column(String(50), index=True)
    package_name: Mapped[str | None] = mapped_column(String(200), index=True)

    # Relationship to vulns
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="affected_products")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    ref_type: Mapped[str | None] = mapped_column(String(50), index=True)
    # ADVISORY, EXPLOIT, PATCH, GITHUB, EXPLOIT_DB, etc.
    source: Mapped[str | None] = mapped_column(String(100))  # like "GitHub", "Exploit-DB", "NVD"

    # Relationship to vulns
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="references")

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

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    exploit_type: Mapped[str | None] = mapped_column(String(50))  # POC, DoS, etc.
    source: Mapped[str | None] = mapped_column(String(100))  # GitHub, Exploit-DB, searchsploit, etc.
    url: Mapped[str | None] = mapped_column(String(1000))
    verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    date_published: Mapped[datetime | None] = mapped_column(DateTime)

    # Relationship to vulns
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="exploits")

    def to_dict(self) -> Dict[str, Any]:
        d_pb = self.date_published.isoformat() if self.date_published else None
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'exploit_type': self.exploit_type, 'source': self.source,
            'url': self.url, 'verified': self.verified,
            'date_published': d_pb
        }


class CISAKEVEntry(Base):
    """CISA Known Exploited Vulnerabilities catalog, filtered feed"""
    __tablename__ = 'cisa_kev'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    date_added: Mapped[datetime | None] = mapped_column(DateTime)
    due_date: Mapped[datetime | None] = mapped_column(DateTime)
    required_action: Mapped[str | None] = mapped_column(Text)
    known_ransomware: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    vendor_project: Mapped[str | None] = mapped_column(String(200))
    product: Mapped[str | None] = mapped_column(String(200))

    # Relationship to vulns
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="cisa_kev")

    def to_dict(self) -> Dict[str, Any]:
        dt_ad = self.date_added.isoformat() if self.date_added else None
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'date_added': dt_ad,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'required_action': self.required_action,
            'known_ransomware': self.known_ransomware,
            'notes': self.notes, 'vendor_project': self.vendor_project,
            'product': self.product
        }


class SandboxRun(Base):
    """execution data for exploits (minimal virtme-ng)"""
    __tablename__ = 'sandbox_runs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    run_timestamp: Mapped[datetime | None] = mapped_column(DateTime)
    sandbox_platform: Mapped[str | None] = mapped_column(String(100))  # virtme-ng, qemu, host
    exploit_file_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    # SHA256 of analyzed file
    execution_success: Mapped[bool] = mapped_column(Boolean, default=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    stdout: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)
    stdin: Mapped[str | None] = mapped_column(Text)
    open_processes: Mapped[Any | None] = mapped_column(JSON)  # List of processes running during execution
    open_files: Mapped[Any | None] = mapped_column(JSON)  # List of files opened during execution
    notes: Mapped[str | None] = mapped_column(Text)

    # Relationship to vulns
    vulnerability: Mapped[Vulnerability] = relationship(back_populates="sandbox_runs")

    def to_dict(self) -> Dict[str, Any]:
        run_t = self.run_timestamp.isoformat() if self.run_timestamp else None
        return {
            'id': self.id, 'vulnerability_id': self.vulnerability_id,
            'run_timestamp': run_t,
            'sandbox_platform': self.sandbox_platform,
            'exploit_file_hash': self.exploit_file_hash,
            'execution_success': self.execution_success,
            'exit_code': self.exit_code,
            'stdout': self.stdout, 'stderr': self.stderr,
            'stdin': self.stdin, 'open_processes': self.open_processes,
            'open_files': self.open_files, 'notes': self.notes
        }


class SecurityRecommendation(Base):
    """security recommendations from lynis/hardening checks"""
    __tablename__ = 'security_recommendations'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    test_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    category: Mapped[str | None] = mapped_column(String(100), index=True)
    description: Mapped[str | None] = mapped_column(Text)
    field_name: Mapped[str | None] = mapped_column(String(200))
    expected_value: Mapped[str | None] = mapped_column(Text)
    actual_value: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(String(50), index=True)
    severity: Mapped[str | None] = mapped_column(String(50), index=True)
    source: Mapped[str | None] = mapped_column(String(100))
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'test_id': self.test_id,
            'category': self.category, 'description': self.description,
            'field_name': self.field_name,
            'expected_value': self.expected_value,
            'actual_value': self.actual_value,
            'status': self.status, 'severity': self.severity,
            'source': self.source, 'raw_data': self.raw_data or {},
            'created_at': self.created_at.isoformat()
            if self.created_at else None
        }


class ThreatIntelligenceORM:
    """db manager"""

    def __init__(self, db_url: str = "sqlite:///ti.db"):
        self.engine = create_engine(
            db_url,
            connect_args={
                "check_same_thread": False
            } if db_url.startswith("sqlite") else {},
            poolclass=StaticPool if db_url == "sqlite:///:memory:" else None
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine)
        self.ScopedSession = scoped_session(self.SessionLocal)
        logger.debug(f"conn setup to TI DB by {db_url}")

    def get_session(self) -> Session:
        return self.SessionLocal()

    def upsert_vulnerability(self, data: Dict[str, Any]) -> Vulnerability:
        """add or update vulnerability"""
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=data['cve_id']).first()
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
            logger.info(f"vulnerability {vuln.id} added to TI DB")
            logger.debug(f"vulnerability {vuln.id} added to TI DB with: {vuln}")
            return vuln
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def get_vulnerability(self, cve_id: str) -> Optional[Vulnerability]:
        session = self.get_session()
        try:
            return session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
        finally:
            session.close()

    def get_vulnerability_with_details(
        self, cve_id: str
    ) -> Optional[Dict[str, Any]]:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                return None

            result = vuln.to_dict()
            kev_stat = vuln.cisa_kev.to_dict() if vuln.cisa_kev else None
            result['affected_products'] = [
                p.to_dict() for p in vuln.affected_products
            ]
            result['references'] = [r.to_dict() for r in vuln.references]
            result['exploits'] = [e.to_dict() for e in vuln.exploits]
            result['cisa_kev'] = kev_stat
            result['sandbox_runs'] = [s.to_dict() for s in vuln.sandbox_runs]

            logger.debug(f"vulnerability {vuln.id} found in TI DB with details: {result}")
            return result
        finally:
            session.close()

    def add_affected_product(
        self, cve_id: str, product_data: Dict[str, Any]
    ) -> AffectedProduct:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            product = AffectedProduct(
                vulnerability_id=vuln.id, **product_data)
            session.add(product)

            session.commit()
            session.refresh(product)
            logger.info(f"vulnerability {cve_id} affected product added to TI DB")
            logger.debug(
                f"{cve_id} affected product {product.id} added to TI DB with: {product}"
            )
            return product
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def add_reference(
        self, cve_id: str, url: str,
        ref_type: str = "OTHER", source: str | None = None
    ) -> Reference:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            # Update counts
            if ref_type == "GITHUB" or source == "GitHub":
                vuln.github_refs += 1
            elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
                vuln.exploitdb_refs += 1

            ref = Reference(
                vulnerability_id=vuln.id, url=url,
                ref_type=ref_type, source=source)
            session.add(ref)

            vuln.calculate_criticality()
            session.commit()
            session.refresh(ref)
            logger.info(f"{cve_id} reference added to TI DB and recalculated criticality")
            logger.debug(f"{cve_id} reference with: {ref}")
            return ref
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def add_exploit(
        self, cve_id: str, exploit_data: Dict[str, Any]
    ) -> Optional[Exploit]:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.warning(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")
            exploit = Exploit(vulnerability_id=vuln.id, **exploit_data)
            session.add(exploit)

            # update flags
            vuln.has_exploit = True
            vuln.exploit_count = session.query(
                Exploit
            ).filter_by(vulnerability_id=vuln.id).count() + 1
            vuln.calculate_criticality()

            session.commit()
            session.refresh(exploit)
            logger.info(f"{cve_id} exploit added to TI DB and recalculated criticality")
            logger.debug(f"{cve_id} exploit with: {exploit}")
            return exploit
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def add_cisa_kev(
        self, cve_id: str, kev_data: Dict[str, Any]
    ) -> CISAKEVEntry | None:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                return None

            # Check for existing KEV entry
            existing = session.query(
                CISAKEVEntry
            ).filter_by(vulnerability_id=vuln.id).first()

            if existing:
                # Update existing entry
                for key, value in kev_data.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                kev = existing
            else:
                # Create new entry
                kev = CISAKEVEntry(vulnerability_id=vuln.id, **kev_data)
                session.add(kev)

            # Update flags
            vuln.in_cisa_kev = True
            vuln.calculate_criticality()

            session.commit()
            session.refresh(kev)
            logger.info(f"{cve_id} is KEV added to TI DB and recalculated criticality ")
            logger.debug(f"{cve_id} is KEV with: {kev}")
            return kev
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def add_sandbox_run(
        self, cve_id: str, sandbox_data: Dict[str, Any]
    ) -> SandboxRun:
        """Add sandbox execution data"""
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.warning(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            sandbox_run = SandboxRun(
                vulnerability_id=vuln.id, **sandbox_data)
            session.add(sandbox_run)
            session.commit()
            session.refresh(sandbox_run)
            logger.info(f"isolated sandbox run added to TI DB")
            logger.debug(f"isolated sandbox run with: {sandbox_run}")
            return sandbox_run
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def get_sandbox_runs(self, cve_id: str) -> List[Dict[str, Any]]:
        session = self.get_session()
        try:
            vuln = session.query(
                Vulnerability
            ).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"st1 {cve_id} sandbox runs not found in TI DB")
                return []

            runs = session.query(SandboxRun).filter_by(
                vulnerability_id=vuln.id
            ).order_by(SandboxRun.run_timestamp.desc()).all()

            return [run.to_dict() for run in runs]
        finally:
            session.close()

    def search(
        self, min_cvss: float | int | None = None, severity: str | None = None,
        has_exploit: bool | None = None, in_cisa_kev: bool | None = None,
        min_criticality: int | None = None, vendor: str | None = None,
        product: str | None = None, package_ecosystem: str | None = None,
        limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """search vulns with filters"""
        session = self.get_session()
        try:
            query = session.query(Vulnerability)

            if min_cvss is not None:
                query = query.filter(
                    Vulnerability.cvss_v3_score >= min_cvss)
            if severity:
                query = query.filter(
                    Vulnerability.severity == severity)
            if has_exploit is not None:
                query = query.filter(
                    Vulnerability.has_exploit == True
                )
            if in_cisa_kev is not None:
                query = query.filter(
                    Vulnerability.in_cisa_kev == True
                )
            if min_criticality is not None:
                query = query.filter(
                    Vulnerability.criticality_score >= min_criticality)
            if vendor or product or package_ecosystem:
                query = query.join(AffectedProduct)
                if vendor:
                    query = query.filter(
                        AffectedProduct.vendor.like(f"%{vendor}%"))
                if product:
                    query = query.filter(
                        AffectedProduct.product.like(f"%{product}%"))
                if package_ecosystem:
                    query = query.filter(
                        AffectedProduct.package_ecosystem == package_ecosystem)

            # order by criticality and CVSS
            query = query.order_by(
                Vulnerability.criticality_score.desc(),
                Vulnerability.cvss_v3_score.desc()
            )

            results = query.limit(limit).offset(offset).all()
            ret_res = [v.to_dict() for v in results]
            logger.info(f"found {len(ret_res)} vulnerabilities")
            logger.debug(f"search vulnerabilities results: {ret_res}")
            return ret_res
        finally:
            session.close()

    def get_critical(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.search(min_criticality=60, limit=limit)

    def get_with_exploits(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.search(has_exploit=True, limit=limit)

    def get_cisa_kev_list(
        self, limit: int = 100
    ) -> List[Dict[str, Any]]:
        return self.search(in_cisa_kev=True, limit=limit)

    def get_statistics(self) -> Dict[str, Any]:
        session = self.get_session()
        try:
            stats: dict[str, Any] = {}

            stats['total'] = session.query(Vulnerability).count()
            severity_counts = session.query(
                Vulnerability.severity,
                func.count(Vulnerability.id)
            ).filter(
                Vulnerability.severity.isnot(None)
            ).group_by(Vulnerability.severity).all()
            stats['by_severity'] = dict(severity_counts)

            stats['with_exploits'] = session.query(
                Vulnerability
            ).filter_by(has_exploit=True).count()
            stats['in_cisa_kev'] = session.query(
                Vulnerability
            ).filter_by(in_cisa_kev=True).count()
            stats['ransomware_related'] = session.query(
                CISAKEVEntry
            ).filter_by(known_ransomware=True).count()
            stats['critical_count'] = session.query(
                Vulnerability
            ).filter(Vulnerability.criticality_score >= 60).count()

            avg_cvss = session.query(
                func.avg(Vulnerability.cvss_v3_score)).scalar()
            stats['avg_cvss'] = round(avg_cvss, 2) if avg_cvss else 0

            logger.debug(f"TI DB statistics: {stats}")
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
                    logger.error(f"inserting {vuln_data.get('cve_id')}: {e}")
            session.commit()
            logger.debug(f"bulk insert vulnerabilities completed: {count}")
            return count
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def add_security_recommendation(
        self, rec_data: SecurityRecommendation
    ) -> SecurityRecommendation:
        """add security recommendation"""
        session = self.get_session()
        try:
            session.add(rec_data)
            session.commit()
            session.refresh(rec_data)
            logger.debug(f"result data: {rec_data}")
            return rec_data
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def bulk_insert_recommendations(
        self, recommendations: List[SecurityRecommendation]
    ) -> int:
        """bulk insert security recommendations"""
        count = 0
        for rec in recommendations:
            try:
                self.add_security_recommendation(rec)
                count += 1
            except Exception as e:
                logger.warning(f"Error inserting rec {rec.test_id}: {e}")
        return count

    def get_security_recommendations(
        self, category: str | None = None, status: str | None = None,
        limit: int = 100, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """get security recommendations with filters"""
        session = self.get_session()
        try:
            query = session.query(SecurityRecommendation)
            if category:
                query = query.filter_by(category=category)
            if status:
                query = query.filter_by(status=status)
            query = query.order_by(
                SecurityRecommendation.severity.desc(),
                SecurityRecommendation.test_id.asc()
            )
            results = query.limit(limit).offset(offset).all()
            return [r.to_dict() for r in results]
        finally:
            session.close()

    def get_recommendations_stats(self) -> Dict[str, Any]:
        """get security recommendations statistics"""
        session = self.get_session()
        try:
            stats = {}
            stats['total'] = session.query(SecurityRecommendation).count()

            cat_q = session.query(
                SecurityRecommendation.category,
                func.count(SecurityRecommendation.id)
            ).filter(
                SecurityRecommendation.category.isnot(None)
            ).group_by(SecurityRecommendation.category).all()
            stats['by_category'] = dict(cat_q)

            stat_q = session.query(
                SecurityRecommendation.status,
                func.count(SecurityRecommendation.id)
            ).filter(
                SecurityRecommendation.status.isnot(None)
            ).group_by(SecurityRecommendation.status).all()
            stats['by_status'] = dict(stat_q)

            sev_q = session.query(
                SecurityRecommendation.severity,
                func.count(SecurityRecommendation.id)
            ).filter(
                SecurityRecommendation.severity.isnot(None)
            ).group_by(SecurityRecommendation.severity).all()
            stats['by_severity'] = dict(sev_q)

            logger.debug(f"recommendations / params stats: {stats}")
            return stats
        finally:
            session.close()

    def close(self):
        self.ScopedSession.remove()
        self.engine.dispose()
        logger.debug("db connection is closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
