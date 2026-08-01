from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import (
    create_engine,
    func,
)
from sqlalchemy.orm import (
    Session,
    scoped_session,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool

from db.models import (
    AffectedProduct,
    Base,
    CISAKEVEntry,
    Exploit,
    Reference,
    SandboxRun,
    SecurityRecommendation,
    Vulnerability,
)

logger = logging.getLogger(f"kernel_audit.{__name__}")


class ThreatIntelligenceORM:
    """db manager"""

    def __init__(self, db_url: str = "sqlite:///ti.db"):
        self.engine = create_engine(
            db_url,
            connect_args=(
                {"check_same_thread": False} if db_url.startswith("sqlite") else {}
            ),
            poolclass=StaticPool if db_url == "sqlite:///:memory:" else None,
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self.ScopedSession = scoped_session(self.SessionLocal)
        logger.debug(f"conn setup to TI DB by {db_url}")

    def get_session(self) -> Session:
        return self.SessionLocal()

    def upsert_vulnerability(self, data: dict[str, Any]) -> Vulnerability:
        """add or update vulnerability"""
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=data["cve_id"]).first()
            if vuln:
                for key, value in data.items():
                    if hasattr(vuln, key) and key != "id":
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

    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        session = self.get_session()
        try:
            return session.query(Vulnerability).filter_by(cve_id=cve_id).first()
        finally:
            session.close()

    def get_vulnerability_with_details(self, cve_id: str) -> dict[str, Any] | None:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                return None

            result = vuln.to_dict()
            kev_stat = vuln.cisa_kev.to_dict() if vuln.cisa_kev else None
            result["affected_products"] = [p.to_dict() for p in vuln.affected_products]
            result["references"] = [r.to_dict() for r in vuln.references]
            result["exploits"] = [e.to_dict() for e in vuln.exploits]
            result["cisa_kev"] = kev_stat
            result["sandbox_runs"] = [s.to_dict() for s in vuln.sandbox_runs]

            logger.debug(
                f"vulnerability {vuln.id} found in TI DB with details: {result}"
            )
            return result
        finally:
            session.close()

    def add_affected_product(
        self, cve_id: str, product_data: dict[str, Any]
    ) -> AffectedProduct:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            product = AffectedProduct(vulnerability_id=vuln.id, **product_data)
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
        self, cve_id: str, url: str, ref_type: str = "OTHER", source: str | None = None
    ) -> Reference:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            # Update counts
            if ref_type == "GITHUB" or source == "GitHub":
                vuln.github_refs += 1
            elif ref_type == "EXPLOIT_DB" or source == "Exploit-DB":
                vuln.exploitdb_refs += 1

            ref = Reference(
                vulnerability_id=vuln.id, url=url, ref_type=ref_type, source=source
            )
            session.add(ref)

            vuln.calculate_criticality()
            session.commit()
            session.refresh(ref)
            logger.info(
                f"{cve_id} reference added to TI DB and recalculated criticality"
            )
            logger.debug(f"{cve_id} reference with: {ref}")
            return ref
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def add_exploit(
        self, cve_id: str, exploit_data: dict[str, Any]
    ) -> Exploit | None:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.warning(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")
            exploit = Exploit(vulnerability_id=vuln.id, **exploit_data)
            session.add(exploit)

            # update flags
            vuln.has_exploit = True
            vuln.exploit_count = (
                session.query(Exploit).filter_by(vulnerability_id=vuln.id).count() + 1
            )
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
        self, cve_id: str, kev_data: dict[str, Any]
    ) -> CISAKEVEntry | None:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"vulnerability {cve_id} not found in TI DB")
                return None

            # Check for existing KEV entry
            existing = (
                session.query(CISAKEVEntry).filter_by(vulnerability_id=vuln.id).first()
            )

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

    def add_sandbox_run(self, cve_id: str, sandbox_data: dict[str, Any]) -> SandboxRun:
        """Add sandbox execution data"""
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.warning(f"vulnerability {cve_id} not found in TI DB")
                raise ValueError(f"Vulnerability {cve_id} not found")

            sandbox_run = SandboxRun(vulnerability_id=vuln.id, **sandbox_data)
            session.add(sandbox_run)
            session.commit()
            session.refresh(sandbox_run)
            logger.info("isolated sandbox run added to TI DB")
            logger.debug(f"isolated sandbox run with: {sandbox_run}")
            return sandbox_run
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def get_sandbox_runs(self, cve_id: str) -> list[dict[str, Any]]:
        session = self.get_session()
        try:
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if not vuln:
                logger.debug(f"st1 {cve_id} sandbox runs not found in TI DB")
                return []

            runs = (
                session.query(SandboxRun)
                .filter_by(vulnerability_id=vuln.id)
                .order_by(SandboxRun.run_timestamp.desc())
                .all()
            )

            return [run.to_dict() for run in runs]
        finally:
            session.close()

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
    ) -> list[dict[str, Any]]:
        """search vulns with filters"""
        session = self.get_session()
        try:
            query = session.query(Vulnerability)

            if min_cvss is not None:
                query = query.filter(Vulnerability.cvss_v3_score >= min_cvss)
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            if has_exploit is not None:
                query = query.filter(Vulnerability.has_exploit == True)
            if in_cisa_kev is not None:
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
                    query = query.filter(
                        AffectedProduct.package_ecosystem == package_ecosystem
                    )

            # order by criticality and CVSS
            query = query.order_by(
                Vulnerability.criticality_score.desc(),
                Vulnerability.cvss_v3_score.desc(),
            )

            results = query.limit(limit).offset(offset).all()
            ret_res = [v.to_dict() for v in results]
            logger.info(f"found {len(ret_res)} vulnerabilities")
            logger.debug(f"search vulnerabilities results: {ret_res}")
            return ret_res
        finally:
            session.close()

    def get_critical(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.search(min_criticality=60, limit=limit)

    def get_with_exploits(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.search(has_exploit=True, limit=limit)

    def get_cisa_kev_list(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.search(in_cisa_kev=True, limit=limit)

    def get_statistics(self) -> dict[str, Any]:
        session = self.get_session()
        try:
            stats: dict[str, Any] = {"total": session.query(Vulnerability).count()}

            severity_counts = (
                session.query(Vulnerability.severity, func.count(Vulnerability.id))
                .filter(Vulnerability.severity.isnot(None))
                .group_by(Vulnerability.severity)
                .all()
            )

            parsed_severity = {row[0]: row[1] for row in severity_counts}
            stats["by_severity"] = parsed_severity
            logger.debug(f"Parsed severity counts: {parsed_severity}")

            stats["with_exploits"] = (
                session.query(Vulnerability).filter_by(has_exploit=True).count()
            )
            stats["in_cisa_kev"] = (
                session.query(Vulnerability).filter_by(in_cisa_kev=True).count()
            )
            stats["ransomware_related"] = (
                session.query(CISAKEVEntry).filter_by(known_ransomware=True).count()
            )
            stats["critical_count"] = (
                session.query(Vulnerability)
                .filter(Vulnerability.criticality_score >= 60)
                .count()
            )

            avg_cvss = session.query(func.avg(Vulnerability.cvss_v3_score)).scalar()
            stats["avg_cvss"] = round(avg_cvss, 2) if avg_cvss else 0

            logger.debug(f"TI DB statistics: {stats}")
            return stats
        finally:
            session.close()

    def bulk_insert(self, vulnerabilities: list[dict[str, Any]]) -> int:
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

    def add_security_recommendation(self, rec_data: SecurityRecommendation) -> int:
        """add security recommendation"""
        session = self.get_session()
        try:
            session.add(rec_data)
            session.commit()
            session.refresh(rec_data)
            logger.debug(f"result data: {rec_data}")
            return rec_data.id
        except Exception as e:
            session.rollback()
            logger.error(e)
            raise e
        finally:
            session.close()

    def bulk_insert_recommendations(
        self, recommendations: list[SecurityRecommendation]
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
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
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
                SecurityRecommendation.test_id.asc(),
            )
            results = query.limit(limit).offset(offset).all()
            return [r.to_dict() for r in results]
        finally:
            session.close()

    def get_recommendations_stats(self) -> dict[str, Any]:
        """get security recommendations statistics"""
        session = self.get_session()
        try:
            stats: dict[str, Any] = {
                "total": session.query(SecurityRecommendation).count()
            }
            cat_q = (
                session.query(
                    SecurityRecommendation.category,
                    func.count(SecurityRecommendation.id),
                )
                .filter(SecurityRecommendation.category.isnot(None))
                .group_by(SecurityRecommendation.category)
                .all()
            )
            parsed_category = {row[0]: row[1] for row in cat_q}
            stats["by_category"] = parsed_category
            logger.debug(f"Parsed recommendation category stats: {parsed_category}")

            stat_q = (
                session.query(
                    SecurityRecommendation.status, func.count(SecurityRecommendation.id)
                )
                .filter(SecurityRecommendation.status.isnot(None))
                .group_by(SecurityRecommendation.status)
                .all()
            )
            parsed_status = {row[0]: row[1] for row in stat_q}
            stats["by_status"] = parsed_status
            logger.debug(f"Parsed recommendation status stats: {parsed_status}")

            sev_q = (
                session.query(
                    SecurityRecommendation.severity,
                    func.count(SecurityRecommendation.id),
                )
                .filter(SecurityRecommendation.severity.isnot(None))
                .group_by(SecurityRecommendation.severity)
                .all()
            )
            parsed_severity_rec = {row[0]: row[1] for row in sev_q}
            stats["by_severity"] = parsed_severity_rec
            logger.debug(f"Parsed recommendation severity stats: {parsed_severity_rec}")

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
