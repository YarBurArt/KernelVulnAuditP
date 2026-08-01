from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)

from core import calculate_criticality_score


class Base(DeclarativeBase):
    pass

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
    sandbox_platform: Mapped[str | None] = mapped_column(String(100))
    exploit_file_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    execution_success: Mapped[bool] = mapped_column(Boolean, default=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    crashed: Mapped[bool] = mapped_column(Boolean, default=False)

    stdout: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)
    stdin: Mapped[str | None] = mapped_column(Text)

    open_processes: Mapped[Any | None] = mapped_column(JSON)
    open_files: Mapped[Any | None] = mapped_column(JSON)
    modules: Mapped[Any | None] = mapped_column(JSON)
    kernel_info: Mapped[Any | None] = mapped_column(JSON)
    resources: Mapped[Any | None] = mapped_column(JSON)

    notes: Mapped[str | None] = mapped_column(Text)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="sandbox_runs")

    def to_dict(self) -> Dict[str, Any]:
        run_t = self.run_timestamp.isoformat() if self.run_timestamp else None
        return {
            'id': self.id,
            'vulnerability_id': self.vulnerability_id,
            'run_timestamp': run_t,
            'sandbox_platform': self.sandbox_platform,
            'exploit_file_hash': self.exploit_file_hash,
            'execution_success': self.execution_success,
            'exit_code': self.exit_code,
            'crashed': self.crashed,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'stdin': self.stdin,
            'open_processes': self.open_processes,
            'open_files': self.open_files,
            'modules': self.modules,
            'kernel_info': self.kernel_info,
            'resources': self.resources,
            'notes': self.notes
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
